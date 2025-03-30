const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");

module.exports = {
  // 入口文件
  entry: "./src/index.js",

  // 输出文件
  output: {
    path: path.resolve(__dirname, "dist"), // 输出目录
    filename: "bundle.js", // 打包后的文件名
    publicPath: "auto", // 可选：用于开发环境中的静态资源路径
    clean: true,
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: "./public/index.html", // 指定模板文件
      filename: "index.html", // 输出文件名
    }),
  ],
  // 模式（development 或 production）
  mode: "development",

  // 解析模块规则
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/, // 匹配 .js 和 .jsx 文件
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: "babel-loader", // 使用 babel-loader
          options: {
            presets: ["@babel/preset-env", "@babel/preset-react"], // 使用 Babel 预设
          },
        },
      },
      {
        test: /\.css$/, // 匹配 .css 文件
        use: ["style-loader", "css-loader"], // 处理 CSS 文件
      },
      {
        test: /\.(woff|woff2|eot|ttf|otf)$/i,
        type: "asset/resource",
      },
      {
        test: /\.svg$/,
        issuer: /\.[jt]sx?$/,
        use: ["@svgr/webpack"],
      },
    ],
  },

  // 解析扩展名
  resolve: {
    extensions: [".js", ".jsx"], // 自动解析扩展名
  },

  // 开发服务器配置
  devServer: {
    static: {
      directory: path.join(__dirname, "dist"), // 静态文件目录
    },
    compress: true, // 启用 gzip 压缩
    port: 3000, // 端口号
    historyApiFallback: true, // 支持前端路由
    proxy: [
      {
        context: ["/api"],
        target: "http://localhost:8080",
        pathRewrite: { "^/api": "" },
      },
    ],
  },
};
