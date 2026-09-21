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
