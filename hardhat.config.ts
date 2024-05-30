import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
      solidity: {
            compilers: [
                  {
                        version: "0.8.24",
                        settings: {
                              // evmVersion: "istanbul",
                              viaIR: true,
                              optimizer: {
                                    enabled: true,
                                    runs: 1000,
                              },
                        },
                  },
            ],
      },
};

export default config;
