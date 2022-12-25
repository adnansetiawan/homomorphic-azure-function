const paillierBigint = require('paillier-bigint');
module.exports = async function (context, req) {
    const action = req.query.action;
    if(action === 'generate-key')
    {
        try
        {
            const { publicKey, privateKey } = await  paillierBigint.generateRandomKeys(256);
            const pk  = {
                n : publicKey.n.toString(),
                g: publicKey.g.toString()

            };
            const sk  = {
                mu : privateKey.mu.toString(),
                lambda: privateKey.lambda.toString()

            }
            context.res = {
                status: 200,
                body: { 
                    data : {
                        pk : pk,
                        sk : sk

                    } 
                }
            };
        }catch(e)
        {
            context.res = {
                status: 500,
                body: { error: e.toString() }
            };
        }
    }else if(action === 'vote')
    {
        const candidateNo = req.body && req.body.candidateNo;
        const pk  = req.body && req.body.publicKey;
        try
        {
            let n = BigInt(pk.n);
            let g = BigInt(pk.g);
      
            const publicKey = new paillierBigint.PublicKey(n, g);
    
            let encodeVote = EncodeVote(candidateNo);
            let encryptedMessage = publicKey.encrypt(BigInt(encodeVote));
            
            context.res = {
                status: 200,
                body: { data : encryptedMessage.toString() }
            };
        }catch(e)
        {
            context.res = {
                status: 500,
                body: { error: e.toString() }
            };
        }
    }
    else if(action === 'decrypt')
    {
        const ballot = req.body && req.body.ballot;
        const sk  = req.body && req.body.privateKey;
        const pk  = req.body && req.body.publicKey;
      
        try
        {
            let mu = BigInt(sk.mu);
            let lambda = BigInt(sk.lambda);
            let n = BigInt(pk.n);
            let g = BigInt(pk.g);
      
            const publicKey = new paillierBigint.PublicKey(n, g);
    
            const privateKey = new paillierBigint.PrivateKey(lambda, mu, publicKey);
    
            let decryptedMessage = privateKey.decrypt(BigInt(ballot));
            
            context.res = {
                status: 200,
                body: { data : decryptedMessage.toString() }
            };
        }catch(e)
        {
            context.res = {
                status: 500,
                body: { error: e.toString() }
            };
        }
    }else if(action === 'share-key')
    {
        try
        {
            const sss = require('shamirs-secret-sharing')
            const secret =  req.body.data.key;
            const min =  req.body.data.min;
            const max =  req.body.data.max;
            const shares = sss.split(secret, { shares: max, threshold: min })  
            //var m = JSON.stringify(shares);
            
            context.res = {
                status: 200,
                body: { data : shares }
            };
        }catch(e)
        {
            context.res = {
                status: 500,
                body: { error: e.toString() }
            };
        }
    }
    else if(action === 'combine-key')
    {
        try
        {
            const sss = require('shamirs-secret-sharing')
            const shares =  req.body.data.keys;
            const min =  req.body.data.min;
            const max =  req.body.data.max;
            const recovered = sss.combine(shares.slice(min, max))
            
            context.res = {
                status: 200,
                body: { data : recovered.toString() }
            };
        }catch(e)
        {
            context.res = {
                status: 500,
                body: { error: e.toString() }
            };
        }
    }else if(action === "tally")
    {
        try
        {
            const sk  = req.body && req.body.privateKey;
            const pk  = req.body && req.body.publicKey;
            let mu = BigInt(sk.mu);
            let lambda = BigInt(sk.lambda);
            let n = BigInt(pk.n);
            let g = BigInt(pk.g);
            const publicKey = new paillierBigint.PublicKey(n, g);
            const privateKey = new paillierBigint.PrivateKey(lambda, mu, publicKey);
            const  ballots = (req.body && (req.body && req.body.ballots));
            const arrVote = [];
            for(let i = 0; i< ballots.length; i++)
            {
                arrVote.push(BigInt(ballots[i]));
            }
            const encryptedSum = publicKey.addition.apply(publicKey, arrVote);
            const decryptedSum = privateKey.decrypt(encryptedSum);
            const result = '0'+ decryptedSum.toString();
            context.res = {
                status: 200, /* Defaults to 200 */
                body: { data : result.toString() }
            };
        }catch(e)
        {
            context.res = {
                status: 500,
                body: { error: e.toString() }
            };
        }
    }else
    {
         context.res = {
            status: 200
        };
    }
    
}
function EncodeVote(candidateNo) {
    var result = Math.pow(10, (2 * ( parseInt(candidateNo) -1)));
    return result.toString();
}