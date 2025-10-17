'use strict';

const config = require('./config');
const { createAppContext, createHttpService, registerCoreRoutes } = require('./src/app/bootstrap');

(async () => {
  try {
    const context = await createAppContext(config, { logger: console });
    const http = createHttpService(context);
    await registerCoreRoutes(http, context);

    const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 80;
    http.listen(port, () => console.log(`Server listening on ${port}`));
  } catch (err) {
    console.error('Failed to bootstrap application', err);
    process.exit(1);
  }
})();
