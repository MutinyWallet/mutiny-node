const defaultTheme = require('tailwindcss/defaultTheme')

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx}", // Note the addition of the `app` directory.
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      green: '#00D1A0',
      blue: '#6895F5',
      'dark-blue': '#071831',
      red: '#F61D5B',
      white: '#FBF5E9',
      black: '#000000'
    },
    extend: {
      fontFamily: {
        'sans': ['Yantramanav', 'system-ui', ...defaultTheme.fontFamily.sans],
      },
      boxShadow: {
        'button': '2px 2px 4px rgba(0, 0, 0, 0.1), inset 4px 4px 4px rgba(255, 255, 255, 0.25), inset -4px -4px 6px rgba(0, 0, 0, 0.3)',
        'button-inverted': '2px 2px 4px rgba(0, 0, 0, 0.1), inset 4px 4px 4px rgba(0, 0, 0, 0.3), inset -4px -4px 6px rgba(255, 255, 255, 0.25)'
      },
      textShadow: {
        'button-text': '1px 1px 2px rgba(0, 0, 0, 0.15)'
      },
      backgroundImage: {
        'gray-button': 'linear-gradient(192.14deg, #FFFFFF -0.54%, #D9D9D9 101.77%)',
        'blue-button': 'linear-gradient(192.14deg, #6895F5 -0.54%, #3861CE 101.77%);',
        'green-button': 'linear-gradient(192.14deg, #00D1A0 -0.54%, #1EA67F 101.77%);'
      }
    },
  },
  plugins: [],
}