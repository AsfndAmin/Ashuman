const { ethers } = require('hardhat');

async function main() {
 //To deploy the Ashumon contract first time   
    // const Ashumon = await hre.ethers.getContractFactory("Ashumon");
    // const ash = await Ashumon.deploy("ashmon","ash");
    // await ash.deployed();
    // console.log("ashmon deployed to:", ash.address);

//To call the contract after providing contract address
    // const addressAsh = '0x91F5Eee6F9419ae41CE3F8075D1946e03dD18B1f';
    // const Ashumon = await ethers.getContractFactory('Ashumon');
    // const ash = await Ashumon.attach(addressAsh);
    // console.log("ashmon address:", ash.address);

//To deploy ashumanTrade contract
    //deploy ashumanTrade contract
    // const signerAddress = "0xeA29891b492Bd2bb13ab2a57C35650762D2d38e4";
    // const AshumonTrade = await hre.ethers.getContractFactory("AshumonTrade");
    // const ashTrade = await AshumonTrade.deploy(ash.address, signerAddress );
    // await ashTrade.deployed();
    // console.log("ashmonTrade deployed to:", ashTrade.address);
 
//To call the contract by providing contract address    
    const addressTrade = '0x1855EC0352E34883cD152B43c5c46486c10C662b';
    const AshumonTrade = await ethers.getContractFactory('AshumonTrade');
    const ashTrade = await AshumonTrade.attach(addressTrade);
    console.log("ashTrade address:", ashTrade.address);

//creating wallet instance by providing private key to sign the hash
    const PRIV_KEY = "a40289fe12e7209a24790db12ea43fa0bd58a0c5c0741e98fc7b271df7afd148"
    const signer = new ethers.Wallet(PRIV_KEY)

//values to create hash    
    const receiver = "0xeA29891b492Bd2bb13ab2a57C35650762D2d38e4";
    const ratio = 15000002;
    const deadline = 1673999999;
    //const signature

    const hash = await ashTrade.getMessageHash(receiver, ratio, deadline)
    const sig = await signer.signMessage(ethers.utils.arrayify(hash))
    console.log("new signature", sig);
        // Correct signature and message returns true

}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });