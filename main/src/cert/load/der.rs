use color_eyre::eyre;

use crate::cert::MaybeSigned;


impl MaybeSigned {
    pub(super) fn from_der(bytes: Vec<u8>) -> eyre::Result<Self> {
        todo!()
    }
}
