const schnorr = require('./tools-bn128');
const skSmg = new Buffer("097e961933fa62e3fef5cedef9a728a6a927a4b29f06a15c6e6c52c031a6cb2b", 'hex');

function test() {
    let typesArray;
    let parameters;
    typesArray = ['uint256', 'string'];
    parameters = ['2345675643', 'Hello!%'];
    let pk = schnorr.getPKBySk(skSmg);

    console.log("=====pk===hex");
    console.log(pk);

    let s = schnorr.getS(skSmg, typesArray, parameters);
    console.log("=====s===hex");
    console.log(s);

    console.log("=====R===hex");
    console.log(schnorr.getR());

    // sig and verify
    console.log("=====s by raw message===hex");
    let rawMsg = "0x1234";
    let sByRaw = schnorr.getSByRawMsg(skSmg, rawMsg);
    console.log(sByRaw);

    console.log("=====R===hex");
    console.log(schnorr.getR());

    //===================Verify sig=====================
    // success
    console.log("===================Verify sig 1=====================");
    try {
        let ret = schnorr.verifySig(schnorr.getR(), sByRaw, rawMsg, pk);
        if (ret) {
            console.log("verifySig success");
        } else {
            console.log("verifySig fail");
        }
    } catch (err) {
        console.log("verifySig fail");
        console.log(err.toString());
    }
}
test();