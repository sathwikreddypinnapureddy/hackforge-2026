import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  webpack(config, { dev }) {
    if (dev && config.watchOptions?.ignored instanceof RegExp) {
      // Runtime fixture and journal writes must not reload the judge workspace.
      // The scanner still reads these files directly for every scan.
      config.watchOptions = {
        ...config.watchOptions,
        ignored: new RegExp(`${config.watchOptions.ignored.source}|[\\\\/](?:demo-repos|\\.hackforge-data)(?:[\\\\/]|$)`),
      };
    }
    return config;
  },
};

export default nextConfig;
