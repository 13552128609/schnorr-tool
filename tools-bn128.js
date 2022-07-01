const crypto = require('crypto');
const BigInteger = require('bigi');
const ecurve = require('ecurve-bn256');
//const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('bn256g1');
//const ecparams = ecurve.getCurveByName('secp256k1');
const Point = ecurve.Point;
const Web3EthAbi = require('web3-eth-abi');
const LenPtHexString = 130;
const ByteLenOfSk = 32;
const ErrPointNotOnCurve = "Point is not on curve";
const ErrInvalidHexString = "not a hex string";
const ErrInvalidHexStringLen = "Invalid hex string length";

// buffer
const r 			    = new Buffer("e7e59bebdcee876e84d03832544f5a517e96a9e3f60cd8f564bece6719d5af52", 'hex');
// buffer
let R					= baseScarMulti(r);
// console.log('R:', R.toString('hex'));

// sk*G
// return: buff
function baseScarMulti(sk) {
    let curvePt = ecparams.G.multiply(BigInteger.fromBuffer(sk));
    return curvePt.getEncoded(false);
}

// hash
// return:buffer
function h(buff) {
    let sha = crypto.createHash('sha256').update(buff).digest();
    return sha;
}

// get s
// s = r+sk*m
// return: buffer
function getSBuff(sk, m) {
    let rBig = BigInteger.fromBuffer(r);
    let skBig = BigInteger.fromBuffer(sk);
    let mBig = BigInteger.fromBuffer(m);
    let retBig;
    retBig = rBig.add(skBig.multiply(mBig).mod(ecparams.n)).mod(ecparams.n);
    return retBig.toBuffer(32);
}

// return: buffer
function computeM1(M) {
    let M1 = h(M);
    // console.log("M1", M1.toString('hex'));
    return M1;
}

// compute m
// M1=hash(M)
// m=hash(M1||R)
// M: buffer
// R: buffer
// return: buffer
function computem(M1, R) {
    let list = [];
    list.push(M1);
    list.push(R);
    // hash(M1||R)
    // console.log("R", R);
    let m = Buffer.concat(list);
    return h(m)
}

//typesArray:['uint256','string']
//parameters: ['2345675643', 'Hello!%']
//return : buff
function computeM(typesArray, parameters) {
    let mStrHex = Web3EthAbi.encodeParameters(typesArray, parameters);
    return new Buffer(mStrHex.substring(2), 'hex');
}

// return : hexString
function getR() {
    return "0x" + R.toString('hex');
}

// return: hexString
function bufferToHexString(buff) {
    return "0x" + buff.toString('hex');
}

// sk: buff
// return: hexString
function getPKBySk(sk) {
    return bufferToHexString(baseScarMulti(sk));
}

//typesArray:['uint256','string']
//parameters: ['2345675643', 'Hello!%']
//return :hexString
function getS(sk, typesArray, parameters) {
    let MBuff = computeM(typesArray, parameters);
    let M1Buff = computeM1(MBuff);
    let mBuff = computem(M1Buff, R);
    let sBuff = getSBuff(sk, mBuff);
    return bufferToHexString(sBuff);
}

function getSByRawMsg(sk, rawMsg) {

    let MBuff = Buffer.from(rawMsg, 'utf8');
    let M1Buff = computeM1(MBuff);
    let mBuff = computem(M1Buff, R);
    let sBuff = getSBuff(sk, mBuff);
    return bufferToHexString(sBuff);
}

//  random      :hexstring
//  sigS        :hexstring
//  rawMessage  :hexstring
//  pk          :hexstring
// return true,false
function verifySig(random, sigS, rawMessage, pk) {

    if (!isHexString(random)) {
        throw "random:" + ErrInvalidHexString;
    }
    if (!isHexString(sigS)) {
        throw "sigS:" + ErrInvalidHexString;
    }
    if (!isHexString(pk)) {
        throw "pk:" + ErrInvalidHexString;
    }
    // compute  left sG
    let sBuffer = Buffer.from(removePrefix(sigS), 'hex');
    let left = baseScarMultiPt(sBuffer);

    // compute  right R+m*pk
    let ptR;
    ptR = ptFromHex(random);
    let isOnCurve = ecparams.isOnCurve(ptR);
    if (!isOnCurve) {
        throw "random:" + ErrPointNotOnCurve;
    }

    let ptMPk;
    ptMPk = ptFromHex(pk);
    isOnCurve = ecparams.isOnCurve(ptMPk);
    if (!isOnCurve) {
        throw "pk:" + ErrPointNotOnCurve;
    }

    let bnm = getbnMFromRaw(random, rawMessage);

    ptMPk = ptMPk.multiply(bnm);

    let right;
    right = ptR.add(ptMPk);

    isOnCurve = ecparams.isOnCurve(left);
    if (!isOnCurve) {
        throw "left sG:" + ErrPointNotOnCurve;
    }
    isOnCurve = ecparams.isOnCurve(right);
    if (!isOnCurve) {
        throw "right R+m*PK:" + ErrPointNotOnCurve;
    }
    return left.equals(right);
}

function isHexString(hexStr) {
    let str = removePrefix(hexStr);
    if (str.length == 0) {
        return false;
    }
    return /^[A-Fa-f0-9]+$/.test(str) && str.length % 2 == 0;
}

function removePrefix(hexStr) {
    if (hexStr.length < 2) throw ErrInvalidHexString;
    if (hexStr.substring(0, 2) === "0x" || hexStr.substring(0, 2) === "0X") {
        return hexStr.substring(2);
    } else {
        return hexStr;
    }
}

// sk*G
// return: buff
function baseScarMultiPt(sk) {
    let curvePt = ecparams.G.multiply(BigInteger.fromBuffer(sk));
    return curvePt
}

function ptFromHex(hexStr) {
    let hexStrTemp = removePrefix(hexStr);
    let bnX, bnY;
    if (hexStrTemp.length !== LenPtHexString) {
        throw ErrInvalidHexStringLen;
    }
    bnX = BigInteger.fromBuffer(Buffer.from(hexStrTemp.substring(2, 66), 'hex'));
    bnY = BigInteger.fromBuffer(Buffer.from(hexStrTemp.substring(66, LenPtHexString), 'hex'));

    return Point.fromAffine(ecparams, bnX, bnY);
}

function getbnMFromRaw(random, rawMsg) {

    let mBuff = getbnMFromRawBuff(random, rawMsg);
    return BigInteger.fromBuffer(mBuff);
}

function getbnMFromRawBuff(random, rawMsg) {
    let bufRandom = Buffer.from(removePrefix(random), 'hex');
    let bufRawMsg = Buffer.from(rawMsg, 'utf-8');

    let M1Buff = computeM1(bufRawMsg);
    let mBuff = computem(M1Buff, bufRandom);
    return mBuff;
}

module.exports = {
    getS: getS,
    getPKBySk: getPKBySk,
    getR: getR,
    getSByRawMsg:getSByRawMsg,
    verifySig:verifySig,
    isHexString:isHexString
};