use crate::utils::PublicParams;

pub struct Agent {
    public_params: PublicParams,
}

impl Agent {
    pub fn new(public_params: PublicParams) -> Self {
        Agent { public_params }
    }
}
