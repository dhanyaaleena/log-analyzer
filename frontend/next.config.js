/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: "/log-analyzer",
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  }
}

module.exports = nextConfig 