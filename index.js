const app = require('./app');
const port = process.env.PORT || 8889;

app.listen(port, () => {
    console.info(`sso-consumer listening on port ${port}`);
});