/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  // Disable server-side features since we're doing static export
  experimental: {
    appDir: true
  }
}

module.exports = nextConfig 