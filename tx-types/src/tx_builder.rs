//! Software signing adapter for the shared planner.

use crate::lock_resolver::LockMatcher;
use crate::planner::{plan, PlanRequest, PlanResult};
use crate::signer::schnorr_sign_digest;
use crate::{
    Chal, PkhSignatureValue, SchnorrPubkey, SchnorrSignature, Sig, Spend, SpendBody, SpendV0ToV1,
    SpendV1, ZMap, T8,
};

/// Plan and sign using caller-supplied chain and lock policies.
pub fn build_spends(
    request: PlanRequest<'_>,
    matcher: &impl LockMatcher,
    secret: T8,
    public_key: SchnorrPubkey,
) -> Result<PlanResult, String> {
    let mut result = plan(request, matcher).map_err(|error| error.to_string())?;
    if result.final_fee < result.minimum_fee {
        return Err("fee is below the signed transaction minimum".into());
    }
    let mut signed = ZMap::new();
    for (name, spend) in result.spends.map.tap() {
        let spend = match spend.body {
            SpendBody::V1(body) => sign_spend_v1(body, secret.clone(), public_key.clone())?,
            SpendBody::V0ToV1(body) => {
                sign_spend_v0_to_v1(body, secret.clone(), public_key.clone())?
            }
            SpendBody::V0(_) => return Err("planner emits V1 transaction spends".into()),
        };
        signed.put(name, spend);
    }
    result.spends.map = signed;
    Ok(result)
}

pub fn sign_spend_v1(
    mut body: SpendV1,
    secret: T8,
    public_key: SchnorrPubkey,
) -> Result<Spend, String> {
    let pkh = public_key.to_hash();
    let policy = body.witness.lmp.spend_condition().required_pkh_policy();
    let should_sign = policy.is_some_and(|policy| {
        policy.hashes.contains(&pkh)
            && !body.witness.pkh.map.has(&pkh)
            && body.witness.pkh.map.wyt() < policy.threshold
    });
    if !should_sign {
        return Ok(Spend {
            version: 1,
            body: SpendBody::V1(body),
        });
    }
    let digest = body.compute_sig_hash().map_err(|error| error.to_string())?;
    let (chal, sig) = schnorr_sign_digest(secret, public_key.clone(), digest);
    body.witness.pkh.map.put(
        pkh,
        PkhSignatureValue {
            pk: public_key,
            sig: SchnorrSignature {
                chal: Chal { values: chal },
                sig: Sig { values: sig },
            },
        },
    );
    Ok(Spend {
        version: 1,
        body: SpendBody::V1(body),
    })
}

pub fn sign_spend_v0_to_v1(
    mut body: SpendV0ToV1,
    secret: T8,
    public_key: SchnorrPubkey,
) -> Result<Spend, String> {
    let digest = body.compute_sig_hash().map_err(|error| error.to_string())?;
    let (chal, sig) = schnorr_sign_digest(secret, public_key.clone(), digest);
    body.signature.put(
        public_key,
        SchnorrSignature {
            chal: Chal { values: chal },
            sig: Sig { values: sig },
        },
    );
    Ok(Spend {
        version: 0,
        body: SpendBody::V0ToV1(body),
    })
}
