try
{
    const crypto  = require('crypto');
    const express = require('express');
}
catch(e)
{
    //  Try-catch to prevent error in apps/clients, Only needed for servers
}




class RunRest
{
    constructor(config)
    {
        this.groups         = {};
        this.activeKeyIndex = config.activeKeyIndex || 0;
        this.serverAddress  = config.serverAddress  || '';
        this.type           = 'server'

        // Created by app/client => done
        if (this.serverAddress)
        {
            this.type = 'client';
            return;
        };

        this.keys = process.env.RUNREST_KEYS
        ? JSON.parse(process.env.RUNREST_KEYS)
        : this._generateKeys(10);
    }

    _generateKeys(n)
    {
        const keys = [];

        for (let i = 0; i < n; i++)
        {
            const keyPair = crypto.generateKeyPairSync('rsa',
            {
                modulusLength: 2048,
                publicKeyEncoding:  { type: 'pkcs1', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
            });
            keys.push(keyPair);
        }

        process.env.RUNREST_KEYS = JSON.stringify(keys);
        return keys;
    }

    _encrypt(key, data)
    {
        const publicKey = crypto.createPublicKey(key);
        const buffer = Buffer.from(data, 'utf8');
        const encrypted = crypto.publicEncrypt(publicKey, buffer);
        return encrypted.toString('base64');
    }

    _decrypt(key, data)
    {
        const privateKey = crypto.createPrivateKey(key);
        const buffer = Buffer.from(data, 'base64');
        const decrypted = crypto.privateDecrypt(privateKey, buffer);
        return decrypted.toString('utf8');
    }

    addGroup(groupName)
    {
        if(this.type == 'client')
        {
            return;
        }

        if (!process.env[`GROUP_${groupName.toUpperCase()}_PASSWORD`])
        {
            console.error(`Missing environment variable for ${groupName} password.`);
            return;
        }

        const group = {
            functions: [],
            registrationRoute: `/${groupName}/register`,
        };

        this.groups[groupName] = group;

        // Generate random hash for the execution route
        const randomHash     = crypto.randomBytes(16).toString('hex');
        const executionRoute = `/${groupName}/execute-${randomHash}`;

        // Registration route
        const app = express();
        app.post(group.registrationRoute, async (req, res) =>
        {
            if (req.body.password === process.env[`GROUP_${groupName.toUpperCase()}_PASSWORD`])
            {
                const tokens = this.keys.map((keyPair) =>
                {
                    const  uniqueHash     = crypto.randomBytes(16).toString('hex');
                    const  tokenData      = `${groupName}-${uniqueHash}`;
                    const  encryptedToken = this._encrypt(keyPair.publicKey, tokenData);
                    return encryptedToken;
                });

                res.json({ id: tokens, executionRoute: executionRoute });
            }
            else
            {
                res.status(401).json({ error: 'Invalid password' });
            }
        });


        // Execution route
        app.post(executionRoute, async (req, res) =>
        {
            const decryptedId = this._decrypt(this.keys[this.activeKeyIndex].privateKey, req.body.id[this.activeKeyIndex]);
            if (decryptedId.startsWith(groupName))
            {
                const fnName = req.body.fn;
                const fn     = group.functions.find((f) => f.name === fnName);
                if (fn)
                {
                    try
                    {
                        const result = await fn(req.body.arg); // OBS might not work yet since it is a stirng?
                        res.json({ result });
                    }
                    catch (error)
                    {
                        res.status(500).json({ error: error.message });
                    }
                }
                else
                {
                    res.status(404).json({ error: `Function "${fnName}" not found` });
                }
            }
            else
            {
                res.status(401).json({ error: 'Invalid token' });
            }
        });
    }


    define(fnRef, groupName)
    {
        if(this.type == 'client')
        {
            return;
        }

        if (!this.groups[groupName])
        {
            console.error(`Group "${groupName}" not found.`);
            return;
        }

        this.groups[groupName].functions.push(fnRef);
    }






    // ------------------- CLIENT/APP PART ----------------------
    async register(groupName, groupPass)
    {
        const response = await fetch(`${this.serverAddress}/${groupName}/register`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: groupPass }),
        });

        if (!response.ok)
        {
            throw new Error(`Server responded with a status of ${response.status}`);
        }

        const data            = await response.json();
        this.registeredGroup  = data; // Save the registration data for later use
    }

    async run(fnName, args)
    {
        if (!this.registeredGroup || !this.registeredGroup.executionRoute)
        {
            throw new Error('Not registered to any group.');
        }

        const requestOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: this.registeredGroup.id, fn: fnName, arg: args, }),
        };

        try
        {
            const response = await fetch(`${this.serverAddress}/${this.registeredGroup.executionRoute}`, requestOptions);
            if (!response.ok)
            {
                throw new Error(`Server responded with a status of ${response.status}`);
            }

            const result = await response.json();
            return result;
        }
        catch (error)
        {
            console.error('Error executing function:', error);
            throw error;
        }
    }
}

module.exports = RunRest;