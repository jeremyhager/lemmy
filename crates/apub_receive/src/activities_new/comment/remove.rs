use crate::{activities_new::comment::send_websocket_message, inbox::new_inbox_routing::Activity};
use activitystreams::activity::kind::RemoveType;
use lemmy_api_common::blocking;
use lemmy_apub::fetcher::objects::get_or_fetch_and_insert_comment;
use lemmy_apub_lib::{PublicUrl, ReceiveActivity};
use lemmy_db_queries::source::comment::Comment_;
use lemmy_db_schema::source::comment::Comment;
use lemmy_utils::LemmyError;
use lemmy_websocket::{LemmyContext, UserOperationCrud};
use url::Url;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveComment {
  actor: Url,
  to: PublicUrl,
  object: Url,
  cc: Vec<Url>,
  #[serde(rename = "type")]
  kind: RemoveType,
}

#[async_trait::async_trait(?Send)]
impl ReceiveActivity for Activity<RemoveComment> {
  async fn receive(
    &self,
    context: &LemmyContext,
    request_counter: &mut i32,
  ) -> Result<(), LemmyError> {
    let comment =
      get_or_fetch_and_insert_comment(&self.inner.object, context, request_counter).await?;

    let removed_comment = blocking(context.pool(), move |conn| {
      Comment::update_removed(conn, comment.id, true)
    })
    .await??;

    // TODO get those recipient actor ids from somewhere
    send_websocket_message(
      removed_comment.id,
      vec![],
      UserOperationCrud::EditComment,
      context,
    )
    .await
  }
}
