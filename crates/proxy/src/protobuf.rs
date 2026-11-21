//! A schema-less protobuf decoder: it reads the wire format without a `.proto` file and
//! guesses what each length-delimited field holds (nested message, UTF-8 text, packed
//! varints or raw bytes), the way `protoc --decode_raw` does.
//!
//! Input is untrusted, so decoding never panics, nests at most [`MAX_DEPTH`] levels, visits
//! at most [`MAX_STEPS`] fields in all (failed guesses included) and keeps at most
//! [`MAX_BYTES_SHOWN`] bytes of each opaque field. Malformed input yields the fields read up
//! to the fault plus an error saying where it was.

use base64::Engine as _;
use serde::Serialize;

/// Deepest nesting of messages decoded; deeper length-delimited fields are left as bytes.
pub const MAX_DEPTH: usize = 16;

/// Fields read per [`decode`] call, counting the ones read while trying a guess that was
/// then dropped. Bounds both time and memory on hostile input.
pub const MAX_STEPS: usize = 20_000;

/// Bytes of an opaque (`bytes`) field kept, base64-encoded, in the tree.
pub const MAX_BYTES_SHOWN: usize = 256;

/// Values a packed-varint guess keeps.
const MAX_PACKED: usize = 256;

/// A decoded message: its fields in wire order, and why decoding stopped early, if it did.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Decoded {
    /// Fields read before the end or the fault.
    pub fields: Vec<Field>,
    /// What was wrong with the input and at which byte offset; `None` when it all parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether a cap ([`MAX_STEPS`]) cut the tree short.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// One field: its number, its wire type and the value read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Field {
    /// The field number from the tag.
    pub field: u32,
    /// `varint`, `i64`, `len` or `i32`, as the protobuf encoding guide names them.
    pub wire: &'static str,
    /// The field name, when a `.proto` schema decoded the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The declared type, such as `int64`, `repeated pkg.Item` or `map<string, int32>`,
    /// when a schema decoded the message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// The oneof the field belongs to, when a schema says so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oneof: Option<String>,
    /// The value, with how it was interpreted.
    #[serde(flatten)]
    pub value: Value,
}

/// A field value. 64-bit integers are decimal strings, since JSON readers often hold
/// numbers as doubles.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Value {
    /// A varint, unsigned and as a zigzag-decoded `sint`.
    Varint {
        /// The value as `uint64`.
        value: String,
        /// The value as `sint64` (zigzag).
        zigzag: String,
    },
    /// Eight little-endian bytes.
    Fixed64 {
        /// The value as `fixed64`.
        value: String,
        /// The same bits as a `double`; `null` in JSON when not finite.
        double: f64,
    },
    /// Four little-endian bytes.
    Fixed32 {
        /// The value as `fixed32`.
        value: u32,
        /// The same bits as a `float`; `null` in JSON when not finite.
        float: f32,
    },
    /// A length-delimited field that parsed as a message.
    Message {
        /// Its fields.
        fields: Vec<Field>,
    },
    /// A length-delimited field that is printable UTF-8.
    String {
        /// The text.
        value: String,
    },
    /// A length-delimited field read as packed varints: a guess, so marked as one.
    PackedVarints {
        /// The values as `uint64`, at most 256 of them.
        values: Vec<String>,
        /// Always `true`: the wire format cannot tell packed varints from bytes.
        guess: bool,
    },
    /// A `bool` field (schema decoding only).
    Bool {
        /// The value.
        value: bool,
    },
    /// A numeric field (schema decoding only), as a decimal string.
    Number {
        /// The value.
        value: String,
    },
    /// An enum field (schema decoding only).
    Enum {
        /// The number on the wire.
        value: i32,
        /// Its name in the schema; `None` for a number the enum does not list. Not `name`,
        /// which the field's own name takes in the flattened JSON.
        symbol: Option<String>,
    },
    /// A `google.protobuf.Struct`, `Value` or `ListValue` (schema decoding only).
    Json {
        /// The JSON it stands for.
        value: serde_json::Value,
    },
    /// A length-delimited field that is none of the above.
    Bytes {
        /// Its length.
        size: usize,
        /// The first [`MAX_BYTES_SHOWN`] bytes, base64.
        base64: String,
        /// Whether `base64` holds less than `size`.
        truncated: bool,
    },
}

/// Decodes `data` as one message, with a fresh budget of [`MAX_STEPS`].
#[must_use]
pub fn decode(data: &[u8]) -> Decoded {
    let mut budget = MAX_STEPS;
    decode_within(data, &mut budget)
}

/// Decodes `data` as one message, spending field visits from `budget`, so several messages
/// can share one cap.
#[must_use]
pub fn decode_within(data: &[u8], budget: &mut usize) -> Decoded {
    let (fields, fault) = parse(data, 0, budget);
    let truncated = matches!(fault, Some(Fault::Budget));
    Decoded {
        fields,
        error: match fault {
            Some(Fault::Malformed { offset, what }) => Some(format!("{what} at byte {offset}")),
            Some(Fault::Budget) | None => None,
        },
        truncated,
    }
}

/// Why parsing a buffer stopped before its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The bytes are not valid protobuf at `offset`.
    Malformed { offset: usize, what: &'static str },
    /// [`MAX_STEPS`] ran out.
    Budget,
}

/// Reads a base-128 varint at `*pos`, advancing it.
fn varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    for shift in (0..64).step_by(7) {
        let byte = *data.get(*pos)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            // The tenth byte may only carry the top bit.
            return (shift < 63 || byte <= 1).then_some(value);
        }
    }
    None
}

fn take<'d>(data: &'d [u8], pos: &mut usize, n: usize) -> Option<&'d [u8]> {
    let end = pos.checked_add(n)?;
    let slice = data.get(*pos..end)?;
    *pos = end;
    Some(slice)
}

/// Parses the fields of `data` at nesting `depth`; stops at the first fault.
fn parse(data: &[u8], depth: usize, budget: &mut usize) -> (Vec<Field>, Option<Fault>) {
    let mut fields = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if *budget == 0 {
            return (fields, Some(Fault::Budget));
        }
        *budget -= 1;
        let start = pos;
        let malformed = |what| {
            Some(Fault::Malformed {
                offset: start,
                what,
            })
        };
        let Some(tag) = varint(data, &mut pos) else {
            return (fields, malformed("bad tag varint"));
        };
        let Ok(number) = u32::try_from(tag >> 3) else {
            return (fields, malformed("field number out of range"));
        };
        if number == 0 || number > 0x1fff_ffff {
            return (fields, malformed("field number out of range"));
        }
        let (wire, value) = match tag & 7 {
            0 => {
                let Some(v) = varint(data, &mut pos) else {
                    return (fields, malformed("truncated varint"));
                };
                let zigzag = (v >> 1).cast_signed() ^ -(v & 1).cast_signed();
                (
                    "varint",
                    Value::Varint {
                        value: v.to_string(),
                        zigzag: zigzag.to_string(),
                    },
                )
            }
            1 => {
                let Some(bytes) = take(data, &mut pos, 8).and_then(|b| <[u8; 8]>::try_from(b).ok())
                else {
                    return (fields, malformed("truncated fixed64"));
                };
                let v = u64::from_le_bytes(bytes);
                (
                    "i64",
                    Value::Fixed64 {
                        value: v.to_string(),
                        double: f64::from_bits(v),
                    },
                )
            }
            2 => {
                let len = varint(data, &mut pos).and_then(|n| usize::try_from(n).ok());
                let Some(bytes) = len.and_then(|n| take(data, &mut pos, n)) else {
                    return (fields, malformed("length past the end"));
                };
                ("len", guess(bytes, depth, budget))
            }
            5 => {
                let Some(bytes) = take(data, &mut pos, 4).and_then(|b| <[u8; 4]>::try_from(b).ok())
                else {
                    return (fields, malformed("truncated fixed32"));
                };
                let v = u32::from_le_bytes(bytes);
                (
                    "i32",
                    Value::Fixed32 {
                        value: v,
                        float: f32::from_bits(v),
                    },
                )
            }
            3 | 4 => return (fields, malformed("groups are not decoded")),
            _ => return (fields, malformed("unknown wire type")),
        };
        fields.push(Field {
            field: number,
            wire,
            name: None,
            proto: None,
            oneof: None,
            value,
        });
    }
    (fields, None)
}

/// What a length-delimited field most likely holds: text if it is printable UTF-8, else a
/// message if all of it parses as one, else packed varints, else bytes.
fn guess(bytes: &[u8], depth: usize, budget: &mut usize) -> Value {
    if let Ok(text) = std::str::from_utf8(bytes)
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
    {
        return Value::String {
            value: text.to_owned(),
        };
    }
    if depth + 1 < MAX_DEPTH && *budget > 0 {
        let (fields, fault) = parse(bytes, depth + 1, budget);
        if fault.is_none() && !fields.is_empty() {
            return Value::Message { fields };
        }
    }
    if let Some(values) = packed(bytes) {
        return Value::PackedVarints {
            values,
            guess: true,
        };
    }
    bytes_value(bytes)
}

/// An opaque field: its size and its first [`MAX_BYTES_SHOWN`] bytes, base64.
pub(crate) fn bytes_value(bytes: &[u8]) -> Value {
    let shown = &bytes[..bytes.len().min(MAX_BYTES_SHOWN)];
    Value::Bytes {
        size: bytes.len(),
        base64: base64::engine::general_purpose::STANDARD.encode(shown),
        truncated: shown.len() < bytes.len(),
    }
}

/// `bytes` as packed varints, if it is a short run of them that ends exactly at the end.
fn packed(bytes: &[u8]) -> Option<Vec<String>> {
    let mut values = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if values.len() == MAX_PACKED {
            return None;
        }
        values.push(varint(bytes, &mut pos)?.to_string());
    }
    (!values.is_empty()).then_some(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic generator (xorshift), so the property tests need no crate.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let len = usize::try_from(self.next()).unwrap_or(0) % max;
            (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
        }
    }

    fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push(u8::try_from(v & 0x7f).unwrap_or(0) | 0x80);
            v >>= 7;
        }
        out.push(u8::try_from(v).unwrap_or(0));
    }

    fn len_field(out: &mut Vec<u8>, number: u64, payload: &[u8]) {
        put_varint(out, number << 3 | 2);
        put_varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    fn depth_of(fields: &[Field]) -> usize {
        fields
            .iter()
            .map(|f| match &f.value {
                Value::Message { fields } => 1 + depth_of(fields),
                _ => 0,
            })
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn decodes_the_encoding_guide_examples() {
        // `Test1 { a: 150 }` and `Test2 { b: "testing" }` from protobuf.dev.
        let d = decode(&[0x08, 0x96, 0x01]);
        assert_eq!(d.error, None);
        assert_eq!(d.fields[0].field, 1);
        assert_eq!(
            d.fields[0].value,
            Value::Varint {
                value: "150".to_owned(),
                zigzag: "75".to_owned()
            }
        );
        let d = decode(&[0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']);
        assert_eq!(
            (d.fields[0].field, d.fields[0].wire, &d.fields[0].value),
            (
                2,
                "len",
                &Value::String {
                    value: "testing".to_owned()
                }
            )
        );
    }

    #[test]
    fn decodes_a_nested_message_with_repeated_and_fixed_fields() {
        // HelloRequest-like: { 1: "world", 2: { 1: 7, 1: 8 }, 3: fixed32 1.5f, 4: fixed64 -2.0 }
        let mut inner = Vec::new();
        put_varint(&mut inner, 1 << 3);
        put_varint(&mut inner, 7);
        put_varint(&mut inner, 1 << 3);
        put_varint(&mut inner, 8);
        let mut msg = Vec::new();
        len_field(&mut msg, 1, b"world");
        len_field(&mut msg, 2, &inner);
        put_varint(&mut msg, 3 << 3 | 5);
        msg.extend_from_slice(&1.5f32.to_le_bytes());
        put_varint(&mut msg, 4 << 3 | 1);
        msg.extend_from_slice(&(-2.0f64).to_le_bytes());
        let d = decode(&msg);
        assert_eq!(d.error, None);
        assert_eq!(d.fields.len(), 4);
        let Value::Message { fields } = &d.fields[1].value else {
            panic!("nested message expected, got {:?}", d.fields[1].value);
        };
        assert_eq!(fields.len(), 2, "repeated field kept twice");
        assert!(
            matches!(d.fields[2].value, Value::Fixed32 { float, .. } if (float - 1.5).abs() < f32::EPSILON)
        );
        assert!(
            matches!(d.fields[3].value, Value::Fixed64 { double, .. } if (double + 2.0).abs() < f64::EPSILON)
        );
        let json = serde_json::to_value(&d).expect("serialisable");
        assert_eq!(json["fields"][1]["type"], "message");
        assert_eq!(json["fields"][0]["wire"], "len");
    }

    #[test]
    fn packed_varints_are_marked_as_a_guess_and_odd_bytes_stay_bytes() {
        let mut msg = Vec::new();
        // 0x01 0x02 0x83 0x01 is not a message (field 0) and not printable.
        len_field(&mut msg, 5, &[0x00, 0x02, 0x83, 0x01]);
        len_field(&mut msg, 6, &[0xff; 300]);
        let d = decode(&msg);
        assert_eq!(
            d.fields[0].value,
            Value::PackedVarints {
                values: vec!["0".to_owned(), "2".to_owned(), "131".to_owned()],
                guess: true
            }
        );
        let Value::Bytes {
            size,
            truncated,
            base64,
        } = &d.fields[1].value
        else {
            panic!("bytes expected");
        };
        assert_eq!((*size, *truncated), (300, true));
        assert_eq!(base64.len(), MAX_BYTES_SHOWN / 3 * 4 + 4);
    }

    #[test]
    fn malformed_input_keeps_the_fields_before_the_fault() {
        let mut msg = Vec::new();
        put_varint(&mut msg, 1 << 3);
        put_varint(&mut msg, 42);
        msg.extend_from_slice(&[0x12, 0x10, b'a']); // length 16, one byte left
        let d = decode(&msg);
        assert_eq!(d.fields.len(), 1);
        assert_eq!(d.error.as_deref(), Some("length past the end at byte 2"));
        assert_eq!(
            decode(&[0x0b]).error.as_deref(),
            Some("groups are not decoded at byte 0")
        );
        assert!(
            decode(&[
                0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
            ])
            .error
            .is_some()
        );
        assert!(decode(&[0x00]).error.is_some(), "field number 0 is invalid");
    }

    #[test]
    fn nesting_stops_at_the_depth_cap() {
        let mut msg = vec![0x08, 0x01];
        for _ in 0..40 {
            let mut outer = Vec::new();
            len_field(&mut outer, 1, &msg);
            msg = outer;
        }
        let d = decode(&msg);
        assert_eq!(d.error, None);
        assert!(
            depth_of(&d.fields) < MAX_DEPTH,
            "depth {}",
            depth_of(&d.fields)
        );
    }

    #[test]
    fn the_step_budget_bounds_huge_flat_messages() {
        let msg: Vec<u8> = std::iter::repeat_n([0x08, 0x01], MAX_STEPS + 10)
            .flatten()
            .collect();
        let d = decode(&msg);
        assert!(d.truncated);
        assert_eq!(d.fields.len(), MAX_STEPS);
    }

    #[test]
    fn random_bytes_never_panic_and_stay_within_the_caps() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..20_000 {
            let data = rng.bytes(200);
            let d = decode(&data);
            assert!(depth_of(&d.fields) < MAX_DEPTH);
            assert!(d.fields.len() <= data.len());
        }
    }

    #[test]
    fn mutated_valid_messages_never_panic() {
        let mut base = Vec::new();
        len_field(&mut base, 1, b"name");
        let mut inner = Vec::new();
        len_field(&mut inner, 2, &[1, 2, 3, 0x80]);
        put_varint(&mut inner, 3 << 3 | 1);
        inner.extend_from_slice(&[0; 8]);
        len_field(&mut base, 4, &inner);
        let mut rng = Rng(42);
        for _ in 0..20_000 {
            let mut data = base.clone();
            for _ in 0..=rng.next() % 4 {
                let at = usize::try_from(rng.next()).unwrap_or(0) % data.len();
                data[at] = rng.next().to_le_bytes()[0];
            }
            let cut = usize::try_from(rng.next()).unwrap_or(0) % (data.len() + 1);
            let d = decode(&data[..cut]);
            assert!(serde_json::to_vec(&d).is_ok());
        }
    }
}
