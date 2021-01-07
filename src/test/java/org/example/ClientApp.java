/*
SPDX-License-Identifier: Apache-2.0
*/

package org.example;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;

public class ClientApp {

    static {
        System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "false");
        System.setProperty("org.hyperledger.fabric.sdk.configuration", Paths.get( "config", "config.properties").toAbsolutePath().toString());
        Security.addProvider(new BouncyCastleProvider());
        Security.removeProvider("SunEC");
    }

    public static void main(String[] args) throws Exception {

        // Load a file system based wallet for managing identities.
        Path walletPath = Paths.get("resources","wallet");
        Wallet wallet = Wallet.createFileSystemWallet(walletPath);

        // load a CCP
        Path networkConfigPath = Paths.get("resources", "connection-org1.yaml");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(wallet, "admin").networkConfig(networkConfigPath).discovery(true);

        // create a gateway connection
        try (Gateway gateway = builder.connect()) {

            // get the network and contract
            Network network = gateway.getNetwork("mychannel");
            Contract contract = network.getContract("mycc");

            byte[] result;

            result = contract.evaluateTransaction("query", "a");
            System.out.println(new String(result));

            contract.submitTransaction("invoke", "a", "b", "1");

            result = contract.evaluateTransaction("query", "a");
            System.out.println(new String(result));

        }
    }

}
