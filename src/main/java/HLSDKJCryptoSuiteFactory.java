/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SDK's Default implementation of CryptoSuiteFactory.
 */
public class HLSDKJCryptoSuiteFactory implements CryptoSuiteFactory {

    private static final Config config = Config.getConfig();
    private static final int SECURITY_LEVEL = config.getSecurityLevel();
    private static final String HASH_ALGORITHM = config.getHashAlgorithm();
    private static final HLSDKJCryptoSuiteFactory INSTANCE = new HLSDKJCryptoSuiteFactory();
    private static final Map<Properties, CryptoSuite> cache = new ConcurrentHashMap<>();
    private static CryptoSuiteFactory theFACTORY = null;

    private HLSDKJCryptoSuiteFactory() {
    }

    @Override
    public CryptoSuite getCryptoSuite(Properties properties) throws CryptoException {
        CryptoSuite ret = cache.get(properties);
        String hashalg = (String) properties.get("org.hyperledger.fabric.sdk.hash_algorithm");
        System.out.println(hashalg);
        if ("SM3".equals(hashalg)) {
            try {
                CryptoSM sm = new CryptoSM();
                sm.setProperties(properties);
                sm.init();
                ret = sm;
            } catch (Exception e) {
                throw new CryptoException(e.getMessage(), e);
            }
            cache.put(properties, ret);
        } else if (ret == null) {
            try {
                ret = CryptoSuiteFactory.getDefault().getCryptoSuite();
            } catch (Exception e) {
                throw new CryptoException(e.getMessage(), e);
            }
            cache.put(properties, ret);
        }

        return ret;
    }

    @Override
    public CryptoSuite getCryptoSuite() throws CryptoException {
        Properties properties = new Properties();
        properties.put(Config.SECURITY_LEVEL, SECURITY_LEVEL);
        properties.put(Config.HASH_ALGORITHM, HASH_ALGORITHM);

        return getCryptoSuite(properties);
    }

    static public synchronized HLSDKJCryptoSuiteFactory instance() {
        return INSTANCE;
    }

    static public synchronized CryptoSuiteFactory getDefault()
        throws ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException {

        if (null == theFACTORY) {
            String cf = config.getDefaultCryptoSuiteFactory();
            if (null == cf || cf.isEmpty() || cf.equals(HLSDKJCryptoSuiteFactory.class.getName())) {
                theFACTORY = HLSDKJCryptoSuiteFactory.instance();
            } else {
                // Invoke static method instance on factory class specified by config properties.
                // In this case this class will no longer be used as the factory.

                Class<?> aClass = Class.forName(cf);
                System.out.println(cf);
                Method method = aClass.getMethod("instance");
                Object theFACTORYObject = method.invoke(null);
                if (null == theFACTORYObject) {
                    throw new InstantiationException(String.format(
                        "Class specified by %s has instance method returning null.  Expected object implementing CryptoSuiteFactory interface.",
                        cf));
                }

                if (!(theFACTORYObject instanceof CryptoSuiteFactory)) {

                    throw new InstantiationException(String.format(
                        "Class specified by %s has instance method returning a class %s which does not implement interface CryptoSuiteFactory ",
                        cf, theFACTORYObject.getClass().getName()));

                }
                theFACTORY = (CryptoSuiteFactory) theFACTORYObject;
            }
        }

        return theFACTORY;
    }

}