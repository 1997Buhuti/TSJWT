import jwt from "jsonwebtoken";

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCsBajXpsn4jBl/UAd/cQglo0UsateAdLzYTWF4Xv+3FT9r6BRE
LnkrSRn/+tGYUiwXbu4zenUM53CmIlCrf4gtAq5s6QDf7HVoIPTkgJIq1G09DJu8
JRwNeyeFpIG/mDUGb43xm0ugSVboa/7cw8svGBq60xSM8bafHgFd28MrvQIDAQAB
AoGAWG4IX+Ozy/tpWBMx54eZoo+ODclWwwg/1AnjY1eiqOFZWwVQ9cPWMjRAE2FC
wcTsOZejB/+ZkGqhdCYLxj2nKHGbWQv87uOKiBrRsOqHDP4lz/lpjHEVQz/iBilb
k1hReuyB3cMwXHSqeEMuKarHGuguPIXpJdCkV9EG0BiQHUECQQD3YyIlWw1pUc/S
xCJQun+YmslJsHuU+6+n0/ZEjXfAZva3dfzJB915+0JJ59ogDW53SbZz2HUmZH1B
81JYWstpAkEAsgLTcHzftxaO6xrkOjUTX01GzFhPTLaLaLEdZiwE8eR/nhmcXVHh
zgtDTqU4lUw+3PWEDzFODO0/nvD+hje3NQJBAJfvQHdk1nXKkzLE1rZx9A+LcPha
9WtosFcIrQUpRVTbZ8cBJcFpnTJfiDTPun1ZAnEsymuXk0uDCBLLF9W/3ZECQQCW
5eRc784pAxtl2ybq3MEuQXCpmpamXfvxZGqaiOgsMVmpKOavCNFUe6Gz0kUT8k07
u3gV9OLH/Hm4/2uTVTmdAkEA3CYJM/U4BSUN6uagMzBuhS7teSUuqhD1Bb7f2fI8
YX7+l4eDqc2r5rsr5vl47Db96JKC6U3hY6XyQqdUK4BAFg==
-----END RSA PRIVATE KEY-----`;

const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsBajXpsn4jBl/UAd/cQglo0Us
ateAdLzYTWF4Xv+3FT9r6BRELnkrSRn/+tGYUiwXbu4zenUM53CmIlCrf4gtAq5s
6QDf7HVoIPTkgJIq1G09DJu8JRwNeyeFpIG/mDUGb43xm0ugSVboa/7cw8svGBq6
0xSM8bafHgFd28MrvQIDAQAB
-----END PUBLIC KEY-----`;

// sign jwt
export function signJWT(payload: object, expiresIn: string | number) {
  return jwt.sign(payload, privateKey, { algorithm: "RS256", expiresIn });
}

// verify jwt
export function verifyJWT(token: string) {
  try {
    const decoded = jwt.verify(token, publicKey);
    return { payload: decoded, expired: false };
  } catch (error) {
    return { payload: null, expired: error.message.includes("jwt expired") };
  }
}
