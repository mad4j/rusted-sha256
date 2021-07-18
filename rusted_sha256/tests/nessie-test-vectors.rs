use std::fmt::Write;

use rusted_sha256::Sha256;

fn to_hex(data: &[u8; 32]) -> String {
    let mut s = String::new();

    for &b in data {
        write!(s, "{:02X}", b).unwrap();
    }

    s
}

#[test]
fn test_nessie_set1_vec0() {
    assert_eq!(
        to_hex(&Sha256::digest(b"")),
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    )
}

#[test]
fn test_nessie_set1_vec1() {
    assert_eq!(
        to_hex(&Sha256::digest(b"a")),
        "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB"
    )
}

#[test]
fn test_nessie_set1_vec2() {
    assert_eq!(
        to_hex(&Sha256::digest(b"abc")),
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    )
}

#[test]
fn test_nessie_set1_vec3() {
    assert_eq!(
        to_hex(&Sha256::digest(b"message digest")),
        "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650"
    )
}

#[test]
fn test_nessie_set1_vec4() {
    assert_eq!(
        to_hex(&Sha256::digest(b"abcdefghijklmnopqrstuvwxyz")),
        "71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73"
    )
}

#[test]
fn test_nessie_set1_vec5() {
    assert_eq!(
        to_hex(&Sha256::digest(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    )
}

#[test]
fn test_nessie_set1_vec6() {
    assert_eq!(
        to_hex(&Sha256::digest(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        )),
        "DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0"
    )
}

#[test]
fn test_nessie_set1_vec7() {
    assert_eq!(
        to_hex(&Sha256::digest(
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        )),
        "F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E"
    )
}

#[test]
fn test_nessie_set1_vec8() {
    assert_eq!(
        to_hex(&Sha256::digest(&[b'a'; 1_000_000])),
        "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"
    )
}
