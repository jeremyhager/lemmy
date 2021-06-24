use crate::{
  activities_new::comment::{get_notif_recipients, send_websocket_message},
  inbox::new_inbox_routing::Activity,
};
use activitystreams::{activity::kind::UpdateType, base::BaseExt};
use anyhow::Context;
use lemmy_apub::{objects::FromApub, NoteExt};
use lemmy_apub_lib::{verify_domains_match, PublicUrl, ReceiveActivity};
use lemmy_db_schema::source::comment::Comment;
use lemmy_utils::{location_info, LemmyError};
use lemmy_websocket::{LemmyContext, UserOperationCrud};
use url::Url;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateComment {
  actor: Url,
  to: PublicUrl,
  object: NoteExt,
  #[serde(rename = "type")]
  kind: UpdateType,
}

#[async_trait::async_trait(?Send)]
impl ReceiveActivity for Activity<UpdateComment> {
  async fn receive(
    &self,
    context: &LemmyContext,
    request_counter: &mut i32,
  ) -> Result<(), LemmyError> {
    verify_domains_match(&self.inner.actor, self.id_unchecked())?;
    verify_domains_match(
      &self.inner.actor,
      self.inner.object.id_unchecked().context(location_info!())?,
    )?;

    let comment = Comment::from_apub(
      &self.inner.object,
      context,
      self.inner.actor.clone(),
      request_counter,
      false,
    )
    .await?;

    let recipients =
      get_notif_recipients(&self.inner.actor, &comment, context, request_counter).await?;
    send_websocket_message(
      comment.id,
      recipients,
      UserOperationCrud::EditComment,
      context,
    )
    .await
  }
}
