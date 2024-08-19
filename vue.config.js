// vue.config.js
module.exports = {
  transpileDependencies: [],

  chainWebpack: config => {
    config.plugin('define')
      .tap(definitions => {
        definitions[0]['process.env'] = {
          ...definitions[0]['process.env'],
          // Define feature flags here
          __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: JSON.stringify(false),
        };
        return definitions;
      });
  }
};
