mod encryption;
pub fn do_it() -> Result<(), Box<dyn std::error::Error>> {
    encryption::poly_proof()?;
    encryption::kjdf_proof()?;
    encryption::x25519_proof()?;
    encryption::blake2_proof()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = do_it();
        assert!(result.is_ok());
    }
}
