module.exports = {
  content: [
    "./src/**/*.{astro,html,js,jsx,ts,tsx,md,mdx}",
    "./node_modules/flowbite/**/*.js",
  ],
  theme: { extend: {} },
  plugins: [require("flowbite/plugin")],
};