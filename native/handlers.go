package native

import (
	"context"
	"encoding/hex"

	tmtypes "github.com/cometbft/cometbft/types"
)

// HandleNewBlock handles the receive of new block from the chain.
func (i *Indexer) HandleNewBlock(ctx context.Context, blk *tmtypes.Block) error {
	// todo set current block

	// and continues to handle a block normally.
	return i.HandleBlock(ctx, blk)
}

// HandleBlock handles the receive of an block from the chain.
func (i *Indexer) HandleBlock(ctx context.Context, blk *tmtypes.Block) error {
	for _, tx := range blk.Data.Txs {
		if err := i.HandleTx(ctx, int(blk.Header.Height), int(blk.Time.Unix()), tx); err != nil {
			i.logger.Err(err).Int64("height", blk.Height).Msg("error handling block")
			continue
		}
	}
	return nil
}

// HandleTx handles the receive of new Tx from the chain.
//
//revive:disable:unused-parameter
func (i *Indexer) HandleTx(ctx context.Context, blockHeight, blockTimeUnix int, tmTx tmtypes.Tx) error {
	tx, err := i.b.DecodeTx(tmTx)
	if err != nil {
		i.logger.Err(err).Msg("error decoding Tx")
		return err
	}

	txHash := tmTx.Hash()
	i.logger.Debug().Msg("handling tx: " + hex.EncodeToString(txHash))

	for _, msg := range tx.GetMsgs() {
		i.logger.Debug().Any("msg", msg).Msg("handling msg")
	}
	return nil
}