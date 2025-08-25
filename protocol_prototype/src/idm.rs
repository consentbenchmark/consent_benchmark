use crate::utils::PublicParams;

pub struct IdentityManager {
    public_params: PublicParams,
}

impl IdentityManager {
    pub fn new(public_params: PublicParams) -> Self {
        IdentityManager { public_params }
    }
}
