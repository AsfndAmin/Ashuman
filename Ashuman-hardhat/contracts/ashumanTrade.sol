// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./Ashumon.sol";

contract AshumonTrade is Ownable {
    using SafeERC20 for Ashumon;
    Ashumon public ashumonToken;
    address signerAddress;
    uint256 base = 10000000;

    // mapping to store paymnet methods
    mapping(uint8 => address) public paymentMethods;

    event TokenMinted(address, uint8, uint256, uint256);
    event TokenRedeemed(address, uint8, uint256, uint256);
    event SignerChanged(address);
    event BaseChanged(uint256);

    constructor(Ashumon tokenContract, address _signerAddress) {
        ashumonToken = tokenContract;
        signerAddress = _signerAddress; 
        // All are Mainnet addresses
        paymentMethods[1] = 0x625B8c5A250b346219758Ad4f2807b8B1015C114;//0xdAC17F958D2ee523a2206206994597C13D831ec7; // USDT address
        paymentMethods[2] = 0x4Fabb145d64652a948d72533023f6E7A623C7C53; // BUSD address
        paymentMethods[3] = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // USDC address
        paymentMethods[4] = 0x6B175474E89094C44Da98b954EedeAC495271d0F; // DAI address
        paymentMethods[5] = 0x853d955aCEf822Db058eb8505911ED77F175b99e; // FRAX address
    }

    /*
     * mint tokens to the msg.sender (caller) address
     * user will receive equivalent tokens of amountIn
     * Requirements:
     * valid payment option
     * passed parameter amountIn must be greater than 0
     */
    function mintToken(
        uint8 paymentOption,
        uint256 amountIn,
        address receiver,
        uint256 ratio,
        uint256 deadline,
        bytes memory signature) external {

        require( 
            deadline > block.timestamp,
            "deadline Passed" 
        );

        require( 
            paymentOption >= 1 && paymentOption <= 5,
            "Invalid payment Option"
        );
        require(amountIn > 10, "Invalid amount");

        //signature verification functionality
        require(verify(receiver, ratio, deadline, signature), "INVALID_SIGNATURE");


        SafeERC20.safeTransferFrom(
            IERC20(paymentMethods[paymentOption]),
            msg.sender,
            address(this),
            amountIn
        );

        uint256 amountOut =(((amountIn * decimal(ashumonToken)*ratio)/
            decimal(Ashumon(paymentMethods[paymentOption])))/base);

        require(amountOut > 0, "zero amountOut");
        ashumonToken.mint(msg.sender, amountOut);

        emit TokenMinted(msg.sender, paymentOption, amountIn, amountOut);
    }

    /*
     * redeem tokens to the msg.sender (caller) address
     * user will receive equivalent tokens of amountIn
     * Requirements:
     * valid redeem option
     * passed parameter amountIn must be greater than 0
     */

    function redeemToken(
        uint8 redeemOption,
        uint256 amountIn ,
        address receiver,
        uint256 ratio,
        uint256 deadline,
        bytes memory signature) external {
        require( 
            deadline > block.timestamp,
            "deadline Passed" 
        );

        require(
            redeemOption >= 1 && redeemOption <= 5,
            "Invalid Redeem Option"
        );
        require(amountIn >= 10, "Invalid amountIn");

        
        //signature verification functionality
        require(verify(receiver, ratio, deadline, signature), "INVALID_SIGNATURE");

        ashumonToken.burn(msg.sender, amountIn);

        // uint256 amountOut = (amountIn *
        //     decimal(Ashumon(paymentMethods[redeemOption]))) /
        //     decimal(ashumonToken);

        uint256 amountOut =(((amountIn * decimal(Ashumon(paymentMethods[redeemOption])))*ratio)/
                           decimal(ashumonToken)/base);
            

        require(amountOut > 0, "zero amountOut");
        SafeERC20.safeTransfer(
            IERC20(paymentMethods[redeemOption]),
            msg.sender,
            amountOut
        );

        emit TokenRedeemed(msg.sender, redeemOption, amountIn, amountOut);
    }

    /*
     * returns decimals of token passed in it as parameter
     */

    function decimal(Ashumon token) internal view returns (uint256) {
        return 10**token.decimals();
    }

        //getting msg hash to generate signature off chian
    function getMessageHash(
        address receiver,
        uint256 ratio,
        uint256 deadline
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(receiver, ratio , deadline));
    }

    //signer functioanlity
        function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function verify(
        address receiver,
        uint256 ratio,
        uint256 deadline,
        bytes memory signature
    ) public view returns (bool) {
        bytes32 messageHash = getMessageHash(receiver, ratio , deadline);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == signerAddress;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature
            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature
            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }



    function setSignerAddress(address _address) external onlyOwner {
        signerAddress = _address;
        emit SignerChanged(_address); 
    }

     function setBase(uint256 _base) external onlyOwner {
         require(_base > 1000000, "base should be greater than 1000000");
         base = _base;
         emit BaseChanged(_base); 
    }
}