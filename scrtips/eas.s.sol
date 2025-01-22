/* solhint-disable no-console */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { console2 } from "forge-std/console2.sol";

import { Script, stdJson } from "forge-std/Script.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ISchemaRegistry, ISchemaResolver } from "@eas/contracts/ISchemaRegistry.sol";
import { IEAS, AttestationRequest, AttestationRequestData } from "@eas/contracts/IEAS.sol";

contract StoryEAS is Script {
    using stdJson for string;
    address public multisig;
    address public deployer;
    address public constant SCHEMA_REGISTRY = address(0xC518620EFB2552FD0B156CaAFdD32f1BfCA83E2E);
    address public constant EAS = address(0xC34dE7Efa031a397F38803415d3986D70a81F6dd);

    bytes32 public constant NAME_SCHEMA_UID =
        bytes32(0x44d562ac1d7cd77e232978687fea027ace48f719cf1d58c7888e509663bb87fc);
    bytes32 public constant IP_PROVENANCE_SCHEMA_ID =
        bytes32(0x59b645f0c0ffa6490f1256a0c1ecfb76eae3bf9adb01f901b144d3ec116dd07e);
    bytes32 public constant INFRINGEMENT_SCHEMA_ID =
        bytes32(0x9f898eca4ae41fb754e11c0062de5a4c6f35b52baa22df17bffa20a0d9fad28e);

    function run() public {
        uint256 multisigPrivateKey;

        multisigPrivateKey = vm.envUint("STORY_MULTISIG_PRIVATEKEY");
        deployer = vm.envAddress("STORY_DEPLOYER_ADDRESS");
        multisig = vm.envAddress("STORY_MULTISIG_ADDRESS");

        vm.startBroadcast(multisigPrivateKey);
        //        _run_register_schema();
        _run_attest();
        vm.stopBroadcast();
    }

    function _run_register_schema() internal {
        ISchemaRegistry schemaRegistry = ISchemaRegistry(SCHEMA_REGISTRY);
        string
            memory ipProvenanceSchema = "address ipId,uint64 registrationDate,uint64 attestationDate,string appName,string appUrl,string price";
        bytes32 ipProvenanceSchemaId = schemaRegistry.register(ipProvenanceSchema, ISchemaResolver(address(0)), true);
        console2.log("IP Provenance Schema ID: ");
        console2.logBytes32(ipProvenanceSchemaId);
        string
            memory infringementSchema = "address ipId,string ipUri,uint64 attestationDate,string providerName,string providerUrl,bool infringementDetected,string infringementDetails,string customData";
        bytes32 infringementSchemaId = schemaRegistry.register(infringementSchema, ISchemaResolver(address(0)), true);
        console2.log("Infringement Schema ID: ");
        console2.logBytes32(infringementSchemaId);

        IEAS eas = IEAS(EAS);
        AttestationRequestData memory ipProvenanceData = AttestationRequestData({
            recipient: address(0),
            expirationTime: 0,
            revocable: true,
            refUID: 0,
            data: abi.encode(ipProvenanceSchemaId, "IP Provenance v1"),
            value: 0
        });
        bytes32 ipProvenanceSchemaNameAttestId = eas.attest(AttestationRequest(NAME_SCHEMA_UID, ipProvenanceData));
        console2.log("IP Provenance Schema Name Attestation ID: ");
        console2.logBytes32(ipProvenanceSchemaNameAttestId);

        AttestationRequestData memory infringementData = AttestationRequestData({
            recipient: address(0),
            expirationTime: 0,
            revocable: true,
            refUID: 0,
            data: abi.encode(infringementSchemaId, "IP Infringement v1"),
            value: 0
        });
        bytes32 infringementSchemaNameAttestId = eas.attest(AttestationRequest(NAME_SCHEMA_UID, infringementData));
        console2.log("Infringement Schema Name Attestation ID: ");
        console2.logBytes32(infringementSchemaNameAttestId);
    }

    function _run_attest() internal {
        IEAS eas = IEAS(EAS);
        AttestationRequestData memory ipProvenanceData = AttestationRequestData({
            recipient: address(0xb5f173bF43F4Fd0D7fE80243d74Ce011F35ECFCB),
            expirationTime: 0,
            revocable: true,
            refUID: 0,
            data: abi.encode(
                address(0xb5f173bF43F4Fd0D7fE80243d74Ce011F35ECFCB),
                uint64(block.timestamp),
                uint64(block.timestamp),
                "My App",
                "http://myapp.com",
                "0.1"
            ),
            value: 0
        });
        bytes32 ipProvenanceAttestId = eas.attest(AttestationRequest(IP_PROVENANCE_SCHEMA_ID, ipProvenanceData));
        console2.log("IP Provenance Attestation ID: ");
        console2.logBytes32(ipProvenanceAttestId);

        AttestationRequestData memory infringementData = AttestationRequestData({
            recipient: address(0xb5f173bF43F4Fd0D7fE80243d74Ce011F35ECFCB),
            expirationTime: 0,
            revocable: true,
            refUID: 0,
            data: abi.encode(
                address(0xb5f173bF43F4Fd0D7fE80243d74Ce011F35ECFCB),
                "http://ipuri.com",
                uint64(block.timestamp),
                "Provider Name",
                "http://provider.com",
                true,
                "Infringement Details",
                "Custom Data"
            ),
            value: 0
        });
        bytes32 infringementAttestId = eas.attest(AttestationRequest(INFRINGEMENT_SCHEMA_ID, infringementData));
        console2.log("Infringement Attestation ID: ");
        console2.logBytes32(infringementAttestId);
    }
}
