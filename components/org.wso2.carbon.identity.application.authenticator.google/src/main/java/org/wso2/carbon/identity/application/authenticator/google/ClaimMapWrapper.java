package org.wso2.carbon.identity.application.authenticator.google;

import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.Map;

public class ClaimMapWrapper {

    private Map<ClaimMapping, String> claimMap;

    public ClaimMapWrapper(Map<ClaimMapping, String> claimMap) {
        this.claimMap = claimMap;
    }

    public void addClaim(String claimId, String claimValue) {
        claimMap.put(ClaimMapping.build(claimId, claimId, null, false), claimValue);
    }

    public String getClaimValue(String claimId) {
        return claimMap.get(ClaimMapping.build(claimId, claimId, null, false));
    }

    public String[] getClaimIds() {
        return (String[]) claimMap.keySet().toArray();
    }
}
