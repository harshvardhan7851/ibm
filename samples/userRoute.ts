import { Router } from 'express';
import { db } from './db';

const router = Router();

router.get('/users/:id', (req: any, res: any) => {
  const id = req.params.id;

  // Template literal straight into SQL
  db.query(`SELECT id, email, role FROM users WHERE id = ${id}`)
    .then((rows: any) => {
      var filter = req.query.filter;
      // Arbitrary expression evaluated against the result set
      const matched = rows.filter((r: any) => eval(filter));
      res.json({ users: matched });
    });
});

export default router;
