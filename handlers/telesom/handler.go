package telesom

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nyaruka/courier"
	"github.com/nyaruka/courier/handlers"
	"github.com/nyaruka/gocommon/dates"
)

var (
	sendURL      = "http://telesom.com/sendsms"
	maxMsgLength = 160
)

func init() {
	courier.RegisterHandler(newHandler())
}

type handler struct {
	handlers.BaseHandler
}

func newHandler() courier.ChannelHandler {
	return &handler{handlers.NewBaseHandler(courier.ChannelType("TS"), "Telesom")}
}

func (h *handler) Initialize(s courier.Server) error {
	h.SetServer(s)
	s.AddHandlerRoute(h, http.MethodGet, "receive", courier.ChannelLogTypeMsgReceive, h.receiveMessage)
	s.AddHandlerRoute(h, http.MethodPost, "receive", courier.ChannelLogTypeMsgReceive, h.receiveMessage)
	return nil
}

type moForm struct {
	Mobile  string `name:"mobile" validate:"required"`
	Message string `name:"msg" validate:"required"`
}

// receiveMessage is our HTTP handler function for incoming messages
func (h *handler) receiveMessage(ctx context.Context, channel courier.Channel, w http.ResponseWriter, r *http.Request, clog *courier.ChannelLog) ([]courier.Event, error) {
	form := &moForm{}
	err := handlers.DecodeAndValidateForm(form, r)
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}
	// create our URN
	urn, err := handlers.StrictTelForCountry(form.Mobile, channel.Country())
	if err != nil {
		return nil, handlers.WriteAndLogRequestError(ctx, h, channel, w, r, err)
	}

	// build our msg
	dbMsg := h.Backend().NewIncomingMsg(channel, urn, form.Message, "", clog)

	// and finally write our message
	return handlers.WriteMsgsAndResponse(ctx, h, []courier.MsgIn{dbMsg}, w, r, clog)

}

func (h *handler) Send(ctx context.Context, msg courier.MsgOut, res *courier.SendResult, clog *courier.ChannelLog) error {
	username := msg.Channel().StringConfigForKey(courier.ConfigUsername, "")
	password := msg.Channel().StringConfigForKey(courier.ConfigPassword, "")
	privateKey := msg.Channel().StringConfigForKey(courier.ConfigSecret, "")
	if username == "" || password == "" || privateKey == "" {
		return courier.ErrChannelConfig
	}
	tsSendURL := msg.Channel().StringConfigForKey(courier.ConfigSendURL, sendURL)

	for _, part := range handlers.SplitMsgByChannel(msg.Channel(), handlers.GetTextAndAttachments(msg), maxMsgLength) {
		from := strings.TrimPrefix(msg.Channel().Address(), "+")
		to := fmt.Sprintf("0%s", strings.TrimPrefix(msg.URN().Localize(msg.Channel().Country()).Path(), "0"))

		// build our request
		form := url.Values{
			"username": []string{username},
			"password": []string{password},
			"to":       []string{to},
			"from":     []string{from},
			"msg":      []string{part},
		}

		date := dates.Now().UTC().Format("02/01/2006")

		hasher := md5.New()
		hasher.Write([]byte(username + "|" + password + "|" + to + "|" + part + "|" + from + "|" + date + "|" + privateKey))
		hash := hex.EncodeToString(hasher.Sum(nil))

		form["key"] = []string{strings.ToUpper(hash)}
		encodedForm := form.Encode()
		tsSendURL = fmt.Sprintf("%s?%s", tsSendURL, encodedForm)

		req, err := http.NewRequest(http.MethodGet, tsSendURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, respBody, err := h.RequestHTTP(req, clog)
		if err != nil || resp.StatusCode/100 == 5 {
			return courier.ErrConnectionFailed
		} else if resp.StatusCode/100 != 2 {
			return courier.ErrResponseStatus
		}

		if !strings.Contains(string(respBody), "Success") {
			clog.Error(courier.NewChannelError("", "", "Received invalid response content: %s", string(respBody)))
			return courier.ErrResponseUnexpected
		}
	}

	return nil
}
