const utils = require('./utils');
const fs = require('fs');

const transfer = ({ transaction }) => {
    let destinations = [
        {
            address: '29611b690efcc913314e9c225bfcded793789c13233de22a8f579667377681d1'
        },
        {
            address: 'ca0561ab3009280918ddca16c001cfce54c4b8e4858b26ffb3d2e78fa8623b06'
        }
    ];

// Read key (address, public key, private key)
    let key = {
        publicKey: '2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d4947664d413047435371475349623344514542415155414134474e4144434269514b42675144534e6e3655504b746953707351692f365756457133472f4b6a0a764a65526c633253426a65476b43647a556b4a514e365364444d6a55616d514b4b5447625371654c436866313739776d736776646555723151756252507733420a5a3255765366437831476e4871687147785553414767675a43574d4a774961416d594b323046504230466e5a476d756c3364556c785139566b6a6367737872630a716465576e464e36496369444d416d346f514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a',
        privateKey: '2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949435841494241414b42675144534e6e3655504b746953707351692f365756457133472f4b6a764a65526c633253426a65476b43647a556b4a514e3653640a444d6a55616d514b4b5447625371654c436866313739776d736776646555723151756252507733425a3255765366437831476e4871687147785553414767675a0a43574d4a774961416d594b323046504230466e5a476d756c3364556c785139566b6a636773787263716465576e464e36496369444d416d346f514944415141420a416f4742414a3534306f6679444d6d32734a75537a6b534b47794662676c6f4a6a4d494743736c77776c39425156786777506b3057586244386f7167416662660a417a53733351326d654658426b3166676c61314c43555649514452554b4253524b33302f63494771757871314c754e322b68747a5a395458316f5867576171430a544c4774584e4379367074725561307a482f654b6f2b33716f6e37507535476b6e5634562f70627977507054506a3735416b4541392b326b4248613665506a540a4539654f66744650392b4732524d77644431766f44364939764d71426969416e56456a795a534f346e6b685750322f33375842317566614744767253486f56660a36426d6e6c766e6d4a774a42414e6b4f67375353594c7a315666614d64446430556a3659516f593449325a51754c66754f64332f6c446946432f354337425a440a6637395868386b4d4e4f6e6e2f3534786532483273554c44547a38564a59476f722f634350335132384b736d2f45473459546a7230642b675064767a3858784f0a4d56454277385751523241336a4945796b547a77394b353045425968306b76714d45306361684c426642574a665054526b434d3734314c6830514a42414e51540a55326e397a316b776d474a426a3165545a727855426b4f6633433665316979594c6141546c4a32346d53512f2f4f3476323052333447723261306a54626255430a41647951725664652f7a48536c6f66643672634351456b42352b3970434c7336362b63735a2f4a533971565348574f6d4e7a5a55305377686f4863326e554b760a6a79374463707130574675394d383547746a64752f657168595a43335036364b754e5a644449436e6747343d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a',
        address: 'ca0561ab3009280918ddca16c001cfce54c4b8e4858b26ffb3d2e78fa8623b06'
    };

    let referenceOutputsHashes = [
        '6d97526dc919784ffabefd21adfffe56ab2384e43e41b085a54f5fd39ee6654c',
    ];

// Generate transacitons
    let bountyTransaction = {
        version: 1,
        inputs: [],
        outputs: []
    };

    let keys = [];

    referenceOutputsHashes.forEach((hash) => {
        bountyTransaction.inputs.push({
            referencedOutputHash: hash,
            referencedOutputIndex: 27,
            unlockScript: ''
        });
        keys.push(key);
    });

// Change because reference output must be use all value
    bountyTransaction.outputs.push({
        value: 1000,
        lockScript: 'ADD ' + destinations[0].address
    });
    bountyTransaction.outputs.push({
        value: 9000,
        lockScript: 'ADD ' + destinations[1].address
    });

// Output to all destination 10000 each
    let sign = transaction({utils});
    sign.sign(bountyTransaction, keys);
    console.log(JSON.stringify(bountyTransaction));
    fs.writeFile('transaction.json', JSON.stringify(bountyTransaction), function () {
       console.log('wrote to file');
    });
};


// Read destination address


// Sign


// Write to file then POST https://api.kcoin.club/transactions
const transaction = require('./transaction');

// => Hash: 6d97526dc919784ffabefd21adfffe56ab2384e43e41b085a54f5fd39ee6654c
transfer({transaction});