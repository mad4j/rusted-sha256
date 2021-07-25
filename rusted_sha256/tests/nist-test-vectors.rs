use hex_literal::hex;
use rusted_sha256::Sha256;

#[test]
fn test_nist_byteoriented_000() {
    assert_eq!(
        Sha256::digest(b""),
        hex!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    )
}
