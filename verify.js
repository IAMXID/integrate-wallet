const router = require("express").Router();
const Blockfrost = require('@blockfrost/blockfrost-js');
const iamx = require('./iamx_methods.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const API = new Blockfrost.BlockFrostAPI({
  projectId: 'mainnetsmgjliTN6Z7sXVkiWCRfDOeWbBxNYjXG', // see: https://blockfrost.io
});
const IPFS = new Blockfrost.BlockFrostIPFS({
  projectId: 'ipfs01dq55gRSrtI0Afph9mmzGvzpoguTWyo', // see: https://blockfrost.io
});

async function getTokenLinkByPolicyId(policyid) {
  let ipfslink = ''
  await axios.get('https://api.koios.rest/api/v0/asset_policy_info', { params: { '_asset_policy': policyid } })
    .then((api_response) => {
      api_response.data.forEach(token => {
        if (token.asset_name == '') {
          if (token.minting_tx_metadata.key == 725) {
            let metadata = token.minting_tx_metadata.json[policyid];
            if (metadata['@context'] == 'https://github.com/IAMXID/did-method-iamx') {
              if (metadata.files.length > 0) {
                ipfslink = metadata.files[0].src.replace('ipfs://', 'https://ipfs.io/ipfs/');
              }
            }
          }
        }
      }
      )
    });
  return ipfslink;
}

async function getJsonFromWebsite(uri) {
  let ipfsdata = ''
  await axios.get(uri)
    .then((api_response) => {
      ipfsdata = api_response.data;
    });
  return ipfsdata;
}

async function getJsonFromIpfs(uri) {
  let ipfsdata = ''
  await axios.get(uri)
    .then((api_response) => {
      ipfsdata = api_response.data;
    });
  return ipfsdata;
}

router.post("/", async (req, res) => {
  try {
    req.body.id = req.body.id.trim();
    let result = {}
    result.accounts = [];
    result.payload = [];
    result.signatures = false;
    let IpfsTokenLink = "";
    //QmeJ9SotNkCtg62PLnwmvokbrpBzjKrBhVHLfFNSgEmkag
    //console.log(req.body.id.length);
    if (req.body.id.length == 46) {
      if (req.body.id.includes("ipfs://") == true) {
        IpfsTokenLink = req.body.id;
      } else {
        IpfsTokenLink = "ipfs://" + req.body.id;
      }
      IpfsTokenLink = IpfsTokenLink.replace('ipfs://', 'https://ipfs.io/ipfs/');
    }
    console.log(IpfsTokenLink);
    if (IpfsTokenLink != "") {
      let IpfsData = await getJsonFromIpfs(IpfsTokenLink);
      console.log(IpfsData.credentialsets);
      // Version String was not signed
      //delete IpfsData.payload.version;
      //console.log(IpfsData.payload);
      result = IpfsData.credentialsets;
      
      let resultSig = iamx.verifyIamxNftSignatureArray2(JSON.stringify(IpfsData.credentialsets), IpfsData.signatures);
      result.signatures = resultSig.allSignaturesOK;
      //console.log(resultSig);
      //return result;
    }
    console.log(result);
    res.status(200).json(result);
  } catch (err) {
    console.log('error', err);
    console.log('error', err.body);
    let errresult = {}
    errresult.accounts = [];
    errresult.signatures = false;
    res.status(200).json(errresult);
  }
});

module.exports = router;
