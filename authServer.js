const app = require('./controller/app');
const port = process.env.PORT || 5000;

app.listen(port, () => {
    console.log(`Authentication server started and accessible via ${port}`);
});
