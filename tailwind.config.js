/** @type {import('tailwindcss').Config} */
const { fontFamily } = require('tailwindcss/defaultTheme');

module.exports = {
  content: [
    './templates/**/*.html',
    './static/css/**/*.css',
    './static/js/**/*.js',
  ],
  theme: {
    container: {
      center: true,
      padding: {
        DEFAULT: '1rem',
        sm: '2rem',
        lg: '4rem',
        xl: '5rem',
      },
    },
    extend: {
      colors: {
        primary: '#041C32',
        secondary: '#00E5FF',
        accent: '#5A4FCF',
        background: '#F8FAFC',
        'text-primary': '#0F172A',
        'text-secondary': '#475569',
        success: '#10B981',
        warning: '#F59E0B',
        error: '#EF4444',
        white: '#FFFFFF',
      },
      fontFamily: {
        sans: ['Poppins', ...fontFamily.sans],
        body: ['Inter', ...fontFamily.sans],
      },
      borderRadius: {
        '4xl': '2rem',
        '5xl': '2.5rem',
        '6xl': '3rem',
      },
      boxShadow: {
        'glow-sm': '0 0 5px rgba(0, 229, 255, 0.5)',
        'glow-md': '0 0 15px rgba(0, 229, 255, 0.5)',
        'glow-lg': '0 0 25px rgba(0, 229, 255, 0.5)',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'pulse-glow': {
          '0%, 100%': {
            boxShadow: '0 0 15px rgba(0, 229, 255, 0.4)',
          },
          '50%': {
            boxShadow: '0 0 25px rgba(0, 229, 255, 0.8)',
          },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.5s ease-out forwards',
        'slide-up': 'slide-up 0.5s ease-out forwards',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
};
