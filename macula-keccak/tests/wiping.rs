//! The reader carries a sponge state from which a short absorbed message
//! can be recovered, so it wipes itself when dropped. The one-shot
//! functions wipe their state before returning; that is by construction,
//! since a value on the stack cannot be observed after the fact from safe
//! code.

#[test]
fn the_reader_wipes_itself_on_drop() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<macula_keccak::Shake128Reader>();
}

/// The absorbing SHAKE256 holds the state and a partial block of what it
/// was given, which in ML-DSA is a secret key; its reader holds the state
/// it squeezes from. Both wipe themselves when dropped.
#[test]
fn shake256_and_its_reader_wipe_themselves_on_drop() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<macula_keccak::Shake256>();
    wipes_on_drop::<macula_keccak::Shake256Reader>();
}
