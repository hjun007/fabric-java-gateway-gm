## About
- **v1.4.6** was tested based on https://github.com/hjun007/fabric-gm-1.4.6.git
- **v2.0.0** was tested based on https://github.com/hjun007/fabric-gm-2.0.0.git
- **feature-ukey** was tested based on https://github.com/hjun007/fabric-gm-2.0.0-dsvs.git

## How to use
```java
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.fabric.gateway.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;

public class ClientApp {

	static {
		System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "false");
		System.setProperty("org.hyperledger.fabric.sdk.configuration", Paths.get("config", "config.properties").toAbsolutePath().toString());
		Security.addProvider(new BouncyCastleProvider());
		Security.removeProvider("SunEC");
	}

	public static void main(String[] args) throws Exception {

		// Load a file system based wallet for managing identities.
		Path walletPath = Paths.get("resources", "whu-cloud", "wallet");
		Wallet wallet = Wallets.newFileSystemWallet(walletPath);

		// load a CCP
		Path networkConfigPath = Paths.get("resources", "whu-cloud", "connection-org1.yaml");

		Gateway.Builder builder = Gateway.createBuilder();
		builder.identity(wallet, "admin").networkConfig(networkConfigPath).discovery(true);

		// create a gateway connection
		try (Gateway gateway = builder.connect()) {

			// get the network and contract
			Network network = gateway.getNetwork("mychannel");
			Contract contract = network.getContract("mycc");

			byte[] result;

			result = contract.evaluateTransaction("Query", "a");
			System.out.println(new String(result));

			contract.submitTransaction("Invoke", "a", "b", "1");

			result = contract.evaluateTransaction("Query", "a");
			System.out.println(new String(result));

		}
	}
}
```