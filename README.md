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
	}

	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		Security.removeProvider("SunEC");
		Path walletPath = Paths.get("resources", "wallet");
		System.out.println(walletPath.toAbsolutePath().toString());
		Wallet wallet = Wallets.newFileSystemWallet(walletPath);
		System.out.println(wallet.list());
		// load a CCP
		Path networkConfigPath = Paths.get("resources","connection-org1.yaml");
		System.setProperty("org.hyperledger.fabric.sdk.configuration",
				Paths.get("config", "config.properties").toAbsolutePath().toString());

		Gateway.Builder builder = Gateway.createBuilder();
		builder.identity(wallet, "admin").networkConfig(networkConfigPath).discovery(true);

		// create a gateway connection
		try (Gateway gateway = builder.connect()) {

			// get the network and contract
			Network network = gateway.getNetwork("mychannel");
			Contract contract = network.getContract("mycc");

			byte[] s = contract.evaluateTransaction("Query", "a");
			System.out.println(new String(s));

			contract.submitTransaction("Invoke", "a", "b", "1");

			s = contract.evaluateTransaction("Query", "a");
			System.out.println(new String(s));

		}
	}
}
```