# integrate-wallet
How to use the Javascript IAMX Wallet interface 


## 1) Connect and request Identity information


### 1.0) Simple Example
Request:
```
window.IAMX.connect({
    did: ""           //mandantory, uniq, always available
    person: {},       //optional, always available response can be 'person' or 'organisation'
    vUID: {}          //optional, uniq, always available
});
```
Response: event('onConnectIAMX')
```
{
  did: "Qmbx9mvPUFSgWkAWBB61GJYZD2twm6P1q6gsu6tJKJacUx",
  person { 
    birthdate: "1979-12-15",
    birthplace: "London",
    firstname: "John Dow",
    id_number: "JD12345",
    issuer: "UK",
    issuing_authority: "UK",
    issuing_date: "2017-04-19",
    lastname: "Dow",
    nationality_iso: "UK",
    valid_until: "2027-04-18",
    verification_level: "2",
    verification_methods: "AI",
    verification_source: "IDCARD",
    verification_timestamp: "2023-04-24T16:17:39+02:00"
  }, 
  vUID { 
    id: "04a43e10e3fce3d1583debdc355d5de6876af34834f67e334ee738583a04642d",
    verification_level: "2",
    verification_methods: "HASH",
    verification_source: "IAMX",
    verification_timestamp: "2023-04-25"
  }
}
``` 


### 1.1) Extended Personal / rKYC Connect
```
window.IAMX.connect({
                did: ""             //mandantory, uniq, always available
                //entity: {},       //optional, always available response can be 'person' or 'organisation'
                //person: {},       //optional, always available  
                //address: {},      //optional, often available
                //tax:{},           //optional, only request tax information if you create taxable events with for the entity
                //domain: {},       //optional
                //email: {},        //optional, often available
                //mobilephone: {},  //optional, often available
                //paypal: {},       //optional, only request payent information if you want to bill them
                //swift: {},        //optional, only request payent information if you want to bill them
                //creditcard: {},   //optional, only request payent information if you want to bill them
                //socialmedia: {},  //optional
                //vUID: {}          //optional, uniq, always available
                });
```


### 1.2) Extended Organisation / rKYB Connect
```
window.IAMX.connect({
                did: ""             //mandantory, uniq, always available
                //entity: {},       //optional, always available response can be 'person' or 'organisation'
                //organisation: {}, //optional, always available   
                //shareholders: {}, //optional, always available   
                //address: {},      //optional, often available
                //tax:{},           //optional, only request tax information if you create taxable events with for the entity
                //domain: {},       //optional
                //email: {},        //optional, often available
                //mobilephone: {},  //optional, often available
                //paypal: {},       //optional, only request payent information if you want to bill them
                //swift: {},        //optional, only request payent information if you want to bill them
                //creditcard: {},   //optional, only request payent information if you want to bill them
                //socialmedia: {},  //optional
                //vUID: {}          //optional, uniq, always available
                });
```


## 2) Verify Identity information

Request:
```
window.IAMX.verifyDID('Qmbx9mvPUFSgWkAWBB61GJYZD2twm6P1q6gsu6tJKJacUx')
```
Response: event('onVerifyDIDIAMX')
```
 {
   hash: 'b37d39cbf311d36d3103756912d9ca3d18184adcde55aac85bb4b059d7d1f2f5',
   signatures: true
 }
```


## 3) Sign Data
Request:
```
window.IAMX.sign('FooBar');
```
Response: event('onSignIAMX')
```
{ 
  signature: 'ur4EalLh2W1kyeHxQw6LNllbwTXCLSqTGRJ7e9umF6eAMbue1g…K5sW8/621eHZT8e1blQjshzNyHl6DhazdUbRFvG3hr3YDXw==',
  publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQE…EpNK01t+k2QZU/v\nZwIDAQAB\n-----END PUBLIC KEY-----'
}
```

## 4) Verify Data Signature

Request:
```
window.IAMX.verify(
  'FooBar',
  '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQE…EpNK01t+k2QZU/v\nZwIDAQAB\n-----END PUBLIC KEY-----',
  'ur4EalLh2W1kyeHxQw6LNllbwTXCLSqTGRJ7e9umF6eAMbue1g…K5sW8/621eHZT8e1blQjshzNyHl6DhazdUbRFvG3hr3YDXw=='
);
```
Response: event('onVerifyIAMX')
```
  { verified: false }
```
