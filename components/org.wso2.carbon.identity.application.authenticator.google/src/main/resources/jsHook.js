var handle = function(claimWrapper) {
    claimWrapper.addClaim("sub", "'JS Hook changed the sub name :)'");
    claimWrapper.addClaim("email", "this value was set by JS Hook");
    claimWrapper.addClaim("country", "proud sri lankan!!!!");
    print("Added a new claim");
};
