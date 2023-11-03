const cookieSession = require("cookie-session");
const express = require("express");
const app = express();
const port = 3033;
const passport = require("passport");
const passportConfig = require("./config/passport-setup");

const verify = require("./routes/verify");

const keys = require("./config/keys");
const cors = require("cors");
const cookieParser = require("cookie-parser"); // parse cookie header
const bodyParser = require("body-parser");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(
  cookieSession({
    name: "nft-identity",
    keys: [keys.COOKIE_KEY],
    maxAge: 24 * 60 * 60 * 100,
  })
);

app.use(cookieParser());

app.use(passport.initialize());
app.use(passport.session());
//passportConfig(passport);
//require("./config/passport-setup")(passport);


var corsOptions = {
  origin: ['https://nftidentity.iamx.id','https://nftlookup.iamx.id','https://vnft.iamx.id','https://handy.de','https://kyc.iamx.id','https://did.iamx.id'],
  credentials: true,
};
//app.use(cors());
//
app.use(function(req, res, next) {
  if(req.headers.origin) {
    console.log('origin',req.headers.origin);
      res.header('Access-Control-Allow-Origin', req.headers.origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Headers','Content-Type, Authorization, x-csrf-token');
  } else {
    res.header('Access-Control-Allow-Origin','*');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers','Content-Type, Authorization, x-csrf-token');
  }
  // intercept OPTIONS method
  if (req.method == 'OPTIONS') {
      res.send(200);
  }
  else {
      next();
  }
});

// set up routes
app.use("/did/verify", didverify);

const authCheck = (req, res, next) => {
  if (!req.user) {
    res.status(401).json({
      authenticated: false,
      message: "user has not been authenticated",
    });
  } else {
    next();
  }
};

app.get("/", (req, res) => {
  res.status(200).json({
    message: "App started",
  });
});

app.listen(process.env.PORT || 5000, () =>
  console.log(`Server is running on port ${process.env.PORT || 5000}!`)
);
