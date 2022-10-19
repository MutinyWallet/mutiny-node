/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      boxShadow: {
        'inner-button': 'inset 4px 4px 4px rgba(255, 255, 255, 0.25) inset -4px -4px 6px rgba(0, 0, 0, 0.3)'
      }
    },
  },
  plugins: [],
}
