use hex_literal::hex;
use rusted_sha256::Sha256;

#[test]
fn test_nonregression_00() {
    assert_eq!(
        Sha256::digest(b"hello world"), 
        hex!("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9")
    )
}
