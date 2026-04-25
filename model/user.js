const pool = require('../controller/database_connection'); //db
const hashing = require('./hash.js');

let User = {
    login: function (loginData) {
        return pool
            .query(
                `SELECT * FROM public.user WHERE username = '${loginData.user}'`
            )
            .then((result) => {
                console.log(result);
                if (result.rows.length == 0) {
                    return { err: 'User does not exist!' };
                } else if (
                    !hashing.compareHash(
                        loginData.pass,
                        result.rows[0].password
                    )
                ) {
                    return { err: 'Invalid password!' };
                } else {
                    return { userId: result.rows[0].user_id };
                }
            });
    },
};

module.exports = User;
