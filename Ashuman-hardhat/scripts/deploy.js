
// const { ethers, upgrades } = require("hardhat");

// async function main() {
//   const fee = 300;
//   const liquidityWallet = "0xeA29891b492Bd2bb13ab2a57C35650762D2d38e4";
//   const companyWallet = "0xeA29891b492Bd2bb13ab2a57C35650762D2d38e4";
//   const holdoutPeriod = 6000;
//   const name = "youbay";
//   const symbol = "yb";
//   const FractionalNftVault = await ethers.getContractFactory("FractionalNftVault");
//   const vault = await upgrades.deployProxy(FractionalNftVault, [fee, liquidityWallet, companyWallet, holdoutPeriod, name, symbol], { initializer: "initialize" });//, {initializer: "initialize"}
//   await vault.deployed();
//   console.log("FractionalNftVault deployed to:", vault.address);
// }

// main();


// main()
//   .then(() => process.exit(0))
//   .catch((error) => {
//     console.error(error);
//     process.exit(1);
//   });
