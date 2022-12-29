#include "dbctx.h"

#include "../../common/file.h"
#include "../../common/log.h"
#include "unqlite_db.h"

using namespace std;

DBBuilder::DBBuilder(const DBCtxOptions& options, const string& base_path)
    : options_(options) { 
  options_.set_db_path(base_path);
}

DBCtx* DBBuilder::Build(const string& sub_path, const string& db_name) {
  auto db_path = options_.db_path() + '/' + sub_path;
  make_dirs(db_path + "/");

  DBCtxOptions options = options_;
  options.set_db_path(db_path);
  options.set_db_name(db_name);

  unique_ptr<DBCtx> ctx;
  auto engine = options_.engine();

  if (engine == DBCtxOptions::LMDB) {
    //ctx.reset(MDBCtx::Create(options);
  }
  if (engine == DBCtxOptions::UNQLITEDB) {
    ctx.reset(UnqliteCtx::Create(options));
  }

  if (DEBUG) {
    log_info("TSDB: open db %s/%s %s.\n", db_path.c_str(), db_name.c_str(),
             ctx ? "succeeded" : "failed");
  }

  if (ctx) ctx->Begin();
  return ctx.release();
}
