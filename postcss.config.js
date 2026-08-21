export default {
  plugins: {
    // Tailwind v4 moved the PostCSS plugin into its own package; naming
    // `tailwindcss` here throws "the PostCSS plugin has moved".
    '@tailwindcss/postcss': {},
    autoprefixer: {},
  },
}
