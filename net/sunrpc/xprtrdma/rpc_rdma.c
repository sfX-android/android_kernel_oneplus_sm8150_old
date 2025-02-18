/*
 * Copyright (c) 2003-2007 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * rpc_rdma.c
 *
 * This file contains the guts of the RPC RDMA protocol, and
 * does marshaling/unmarshaling, etc. It is also where interfacing
 * to the Linux RPC framework lives.
 */

#include "xprt_rdma.h"

#include <linux/highmem.h>

#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
# define RPCDBG_FACILITY	RPCDBG_TRANS
#endif

static const char transfertypes[][12] = {
	"inline",	/* no chunks */
	"read list",	/* some argument via rdma read */
	"*read list",	/* entire request via rdma read */
	"write list",	/* some result via rdma write */
	"reply chunk"	/* entire reply via rdma write */
};

/* Returns size of largest RPC-over-RDMA header in a Call message
 *
 * The largest Call header contains a full-size Read list and a
 * minimal Reply chunk.
 */
static unsigned int rpcrdma_max_call_header_size(unsigned int maxsegs)
{
	unsigned int size;

	/* Fixed header fields and list discriminators */
	size = RPCRDMA_HDRLEN_MIN;

	/* Maximum Read list size */
	maxsegs += 2;	/* segment for head and tail buffers */
	size += maxsegs * sizeof(struct rpcrdma_read_chunk);

	/* Minimal Read chunk size */
	size += sizeof(__be32);	/* segment count */
	size += sizeof(struct rpcrdma_segment);
	size += sizeof(__be32);	/* list discriminator */

	dprintk("RPC:       %s: max call header size = %u\n",
		__func__, size);
	return size;
}

/* Returns size of largest RPC-over-RDMA header in a Reply message
 *
 * There is only one Write list or one Reply chunk per Reply
 * message.  The larger list is the Write list.
 */
static unsigned int rpcrdma_max_reply_header_size(unsigned int maxsegs)
{
	unsigned int size;

	/* Fixed header fields and list discriminators */
	size = RPCRDMA_HDRLEN_MIN;

	/* Maximum Write list size */
	maxsegs += 2;	/* segment for head and tail buffers */
	size += sizeof(__be32);		/* segment count */
	size += maxsegs * sizeof(struct rpcrdma_segment);
	size += sizeof(__be32);	/* list discriminator */

	dprintk("RPC:       %s: max reply header size = %u\n",
		__func__, size);
	return size;
}

void rpcrdma_set_max_header_sizes(struct rpcrdma_xprt *r_xprt)
{
	struct rpcrdma_create_data_internal *cdata = &r_xprt->rx_data;
	struct rpcrdma_ia *ia = &r_xprt->rx_ia;
	unsigned int maxsegs = ia->ri_max_segs;

	ia->ri_max_inline_write = cdata->inline_wsize -
				  rpcrdma_max_call_header_size(maxsegs);
	ia->ri_max_inline_read = cdata->inline_rsize -
				 rpcrdma_max_reply_header_size(maxsegs);
}

/* The client can send a request inline as long as the RPCRDMA header
 * plus the RPC call fit under the transport's inline limit. If the
 * combined call message size exceeds that limit, the client must use
 * a Read chunk for this operation.
 *
 * A Read chunk is also required if sending the RPC call inline would
 * exceed this device's max_sge limit.
 */
static bool rpcrdma_args_inline(struct rpcrdma_xprt *r_xprt,
				struct rpc_rqst *rqst)
{
	struct xdr_buf *xdr = &rqst->rq_snd_buf;
	unsigned int count, remaining, offset;

	if (xdr->len > r_xprt->rx_ia.ri_max_inline_write)
		return false;

	if (xdr->page_len) {
		remaining = xdr->page_len;
		offset = offset_in_page(xdr->page_base);
		count = RPCRDMA_MIN_SEND_SGES;
		while (remaining) {
			remaining -= min_t(unsigned int,
					   PAGE_SIZE - offset, remaining);
			offset = 0;
			if (++count > r_xprt->rx_ia.ri_max_send_sges)
				return false;
		}
	}

	return true;
}

/* The client can't know how large the actual reply will be. Thus it
 * plans for the largest possible reply for that particular ULP
 * operation. If the maximum combined reply message size exceeds that
 * limit, the client must provide a write list or a reply chunk for
 * this request.
 */
static bool rpcrdma_results_inline(struct rpcrdma_xprt *r_xprt,
				   struct rpc_rqst *rqst)
{
	struct rpcrdma_ia *ia = &r_xprt->rx_ia;

	return rqst->rq_rcv_buf.buflen <= ia->ri_max_inline_read;
}

/* Split @vec on page boundaries into SGEs. FMR registers pages, not
 * a byte range. Other modes coalesce these SGEs into a single MR
 * when they can.
 *
 * Returns pointer to next available SGE, and bumps the total number
 * of SGEs consumed.
 */
static struct rpcrdma_mr_seg *
rpcrdma_convert_kvec(struct kvec *vec, struct rpcrdma_mr_seg *seg,
		     unsigned int *n)
{
	u32 remaining, page_offset;
	char *base;

	base = vec->iov_base;
	page_offset = offset_in_page(base);
	remaining = vec->iov_len;
	while (remaining) {
		seg->mr_page = NULL;
		seg->mr_offset = base;
		seg->mr_len = min_t(u32, PAGE_SIZE - page_offset, remaining);
		remaining -= seg->mr_len;
		base += seg->mr_len;
		++seg;
		++(*n);
		page_offset = 0;
	}
	return seg;
}

/* Convert @xdrbuf into SGEs no larger than a page each. As they
 * are registered, these SGEs are then coalesced into RDMA segments
 * when the selected memreg mode supports it.
 *
 * Returns positive number of SGEs consumed, or a negative errno.
 */

static int
rpcrdma_convert_iovs(struct rpcrdma_xprt *r_xprt, struct xdr_buf *xdrbuf,
		     unsigned int pos, enum rpcrdma_chunktype type,
		     struct rpcrdma_mr_seg *seg)
{
	unsigned long page_base;
	unsigned int len, n;
	struct page **ppages;

	n = 0;
	if (pos == 0)
		seg = rpcrdma_convert_kvec(&xdrbuf->head[0], seg, &n);

	len = xdrbuf->page_len;
	ppages = xdrbuf->pages + (xdrbuf->page_base >> PAGE_SHIFT);
	page_base = offset_in_page(xdrbuf->page_base);
	while (len) {
		if (unlikely(!*ppages)) {
			/* XXX: Certain upper layer operations do
			 *	not provide receive buffer pages.
			 */
			*ppages = alloc_page(GFP_ATOMIC);
			if (!*ppages)
				return -ENOBUFS;
		}
		seg->mr_page = *ppages;
		seg->mr_offset = (char *)page_base;
		seg->mr_len = min_t(u32, PAGE_SIZE - page_base, len);
		len -= seg->mr_len;
		++ppages;
		++seg;
		++n;
		page_base = 0;
	}

	/* When encoding a Read chunk, the tail iovec contains an
	 * XDR pad and may be omitted.
	 */
	if (type == rpcrdma_readch && r_xprt->rx_ia.ri_implicit_roundup)
		goto out;

	/* When encoding a Write chunk, some servers need to see an
	 * extra segment for non-XDR-aligned Write chunks. The upper
	 * layer provides space in the tail iovec that may be used
	 * for this purpose.
	 */
	if (type == rpcrdma_writech && r_xprt->rx_ia.ri_implicit_roundup)
		goto out;

	if (xdrbuf->tail[0].iov_len)
		seg = rpcrdma_convert_kvec(&xdrbuf->tail[0], seg, &n);

out:
	if (unlikely(n > RPCRDMA_MAX_SEGS))
		return -EIO;
	return n;
}

static inline int
encode_item_present(struct xdr_stream *xdr)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, sizeof(*p));
	if (unlikely(!p))
		return -EMSGSIZE;

	*p = xdr_one;
	return 0;
}

static inline int
encode_item_not_present(struct xdr_stream *xdr)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, sizeof(*p));
	if (unlikely(!p))
		return -EMSGSIZE;

	*p = xdr_zero;
	return 0;
}

static void
xdr_encode_rdma_segment(__be32 *iptr, struct rpcrdma_mw *mw)
{
	*iptr++ = cpu_to_be32(mw->mw_handle);
	*iptr++ = cpu_to_be32(mw->mw_length);
	xdr_encode_hyper(iptr, mw->mw_offset);
}

static int
encode_rdma_segment(struct xdr_stream *xdr, struct rpcrdma_mw *mw)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 * sizeof(*p));
	if (unlikely(!p))
		return -EMSGSIZE;

	xdr_encode_rdma_segment(p, mw);
	return 0;
}

static int
encode_read_segment(struct xdr_stream *xdr, struct rpcrdma_mw *mw,
		    u32 position)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 6 * sizeof(*p));
	if (unlikely(!p))
		return -EMSGSIZE;

	*p++ = xdr_one;			/* Item present */
	*p++ = cpu_to_be32(position);
	xdr_encode_rdma_segment(p, mw);
	return 0;
}

/* Register and XDR encode the Read list. Supports encoding a list of read
 * segments that belong to a single read chunk.
 *
 * Encoding key for single-list chunks (HLOO = Handle32 Length32 Offset64):
 *
 *  Read chunklist (a linked list):
 *   N elements, position P (same P for all chunks of same arg!):
 *    1 - PHLOO - 1 - PHLOO - ... - 1 - PHLOO - 0
 *
 * Returns zero on success, or a negative errno if a failure occurred.
 * @xdr is advanced to the next position in the stream.
 *
 * Only a single @pos value is currently supported.
 */
static noinline int
rpcrdma_encode_read_list(struct rpcrdma_xprt *r_xprt, struct rpcrdma_req *req,
			 struct rpc_rqst *rqst, enum rpcrdma_chunktype rtype)
{
	struct xdr_stream *xdr = &req->rl_stream;
	struct rpcrdma_mr_seg *seg;
	struct rpcrdma_mw *mw;
	unsigned int pos;
	int nsegs;

	pos = rqst->rq_snd_buf.head[0].iov_len;
	if (rtype == rpcrdma_areadch)
		pos = 0;
	seg = req->rl_segments;
	nsegs = rpcrdma_convert_iovs(r_xprt, &rqst->rq_snd_buf, pos,
				     rtype, seg);
	if (nsegs < 0)
		return nsegs;

	do {
		seg = r_xprt->rx_ia.ri_ops->ro_map(r_xprt, seg, nsegs,
						   false, &mw);
		if (IS_ERR(seg))
			return PTR_ERR(seg);
		rpcrdma_push_mw(mw, &req->rl_registered);

		if (encode_read_segment(xdr, mw, pos) < 0)
			return -EMSGSIZE;

		dprintk("RPC: %5u %s: pos %u %u@0x%016llx:0x%08x (%s)\n",
			rqst->rq_task->tk_pid, __func__, pos,
			mw->mw_length, (unsigned long long)mw->mw_offset,
			mw->mw_handle, mw->mw_nents < nsegs ? "more" : "last");

		r_xprt->rx_stats.read_chunk_count++;
		nsegs -= mw->mw_nents;
	} while (nsegs);

	return 0;
}

/* Register and XDR encode the Write list. Supports encoding a list
 * containing one array of plain segments that belong to a single
 * write chunk.
 *
 * Encoding key for single-list chunks (HLOO = Handle32 Length32 Offset64):
 *
 *  Write chunklist (a list of (one) counted array):
 *   N elements:
 *    1 - N - HLOO - HLOO - ... - HLOO - 0
 *
 * Returns zero on success, or a negative errno if a failure occurred.
 * @xdr is advanced to the next position in the stream.
 *
 * Only a single Write chunk is currently supported.
 */
static noinline int
rpcrdma_encode_write_list(struct rpcrdma_xprt *r_xprt, struct rpcrdma_req *req,
			  struct rpc_rqst *rqst, enum rpcrdma_chunktype wtype)
{
	struct xdr_stream *xdr = &req->rl_stream;
	struct rpcrdma_mr_seg *seg;
	struct rpcrdma_mw *mw;
	int nsegs, nchunks;
	__be32 *segcount;

	seg = req->rl_segments;
	nsegs = rpcrdma_convert_iovs(r_xprt, &rqst->rq_rcv_buf,
				     rqst->rq_rcv_buf.head[0].iov_len,
				     wtype, seg);
	if (nsegs < 0)
		return nsegs;

	if (encode_item_present(xdr) < 0)
		return -EMSGSIZE;
	segcount = xdr_reserve_space(xdr, sizeof(*segcount));
	if (unlikely(!segcount))
		return -EMSGSIZE;
	/* Actual value encoded below */

	nchunks = 0;
	do {
		seg = r_xprt->rx_ia.ri_ops->ro_map(r_xprt, seg, nsegs,
						   true, &mw);
		if (IS_ERR(seg))
			return PTR_ERR(seg);
		rpcrdma_push_mw(mw, &req->rl_registered);

		if (encode_rdma_segment(xdr, mw) < 0)
			return -EMSGSIZE;

		dprintk("RPC: %5u %s: %u@0x016%llx:0x%08x (%s)\n",
			rqst->rq_task->tk_pid, __func__,
			mw->mw_length, (unsigned long long)mw->mw_offset,
			mw->mw_handle, mw->mw_nents < nsegs ? "more" : "last");

		r_xprt->rx_stats.write_chunk_count++;
		r_xprt->rx_stats.total_rdma_request += seg->mr_len;
		nchunks++;
		nsegs -= mw->mw_nents;
	} while (nsegs);

	/* Update count of segments in this Write chunk */
	*segcount = cpu_to_be32(nchunks);

	return 0;
}

/* Register and XDR encode the Reply chunk. Supports encoding an array
 * of plain segments that belong to a single write (reply) chunk.
 *
 * Encoding key for single-list chunks (HLOO = Handle32 Length32 Offset64):
 *
 *  Reply chunk (a counted array):
 *   N elements:
 *    1 - N - HLOO - HLOO - ... - HLOO
 *
 * Returns zero on success, or a negative errno if a failure occurred.
 * @xdr is advanced to the next position in the stream.
 */
static noinline int
rpcrdma_encode_reply_chunk(struct rpcrdma_xprt *r_xprt, struct rpcrdma_req *req,
			   struct rpc_rqst *rqst, enum rpcrdma_chunktype wtype)
{
	struct xdr_stream *xdr = &req->rl_stream;
	struct rpcrdma_mr_seg *seg;
	struct rpcrdma_mw *mw;
	int nsegs, nchunks;
	__be32 *segcount;

	seg = req->rl_segments;
	nsegs = rpcrdma_convert_iovs(r_xprt, &rqst->rq_rcv_buf, 0, wtype, seg);
	if (nsegs < 0)
		return nsegs;

	if (encode_item_present(xdr) < 0)
		return -EMSGSIZE;
	segcount = xdr_reserve_space(xdr, sizeof(*segcount));
	if (unlikely(!segcount))
		return -EMSGSIZE;
	/* Actual value encoded below */

	nchunks = 0;
	do {
		seg = r_xprt->rx_ia.ri_ops->ro_map(r_xprt, seg, nsegs,
						   true, &mw);
		if (IS_ERR(seg))
			return PTR_ERR(seg);
		rpcrdma_push_mw(mw, &req->rl_registered);

		if (encode_rdma_segment(xdr, mw) < 0)
			return -EMSGSIZE;

		dprintk("RPC: %5u %s: %u@0x%016llx:0x%08x (%s)\n",
			rqst->rq_task->tk_pid, __func__,
			mw->mw_length, (unsigned long long)mw->mw_offset,
			mw->mw_handle, mw->mw_nents < nsegs ? "more" : "last");

		r_xprt->rx_stats.reply_chunk_count++;
		r_xprt->rx_stats.total_rdma_request += seg->mr_len;
		nchunks++;
		nsegs -= mw->mw_nents;
	} while (nsegs);

	/* Update count of segments in the Reply chunk */
	*segcount = cpu_to_be32(nchunks);

	return 0;
}

/* Prepare the RPC-over-RDMA header SGE.
 */
static bool
rpcrdma_prepare_hdr_sge(struct rpcrdma_ia *ia, struct rpcrdma_req *req,
			u32 len)
{
	struct rpcrdma_regbuf *rb = req->rl_rdmabuf;
	struct ib_sge *sge = &req->rl_send_sge[0];

	if (unlikely(!rpcrdma_regbuf_is_mapped(rb))) {
		if (!__rpcrdma_dma_map_regbuf(ia, rb))
			return false;
		sge->addr = rdmab_addr(rb);
		sge->lkey = rdmab_lkey(rb);
	}
	sge->length = len;

	ib_dma_sync_single_for_device(rdmab_device(rb), sge->addr,
				      sge->length, DMA_TO_DEVICE);
	req->rl_send_wr.num_sge++;
	return true;
}

/* Prepare the Send SGEs. The head and tail iovec, and each entry
 * in the page list, gets its own SGE.
 */
static bool
rpcrdma_prepare_msg_sges(struct rpcrdma_ia *ia, struct rpcrdma_req *req,
			 struct xdr_buf *xdr, enum rpcrdma_chunktype rtype)
{
	unsigned int sge_no, page_base, len, remaining;
	struct rpcrdma_regbuf *rb = req->rl_sendbuf;
	struct ib_device *device = ia->ri_device;
	struct ib_sge *sge = req->rl_send_sge;
	u32 lkey = ia->ri_pd->local_dma_lkey;
	struct page *page, **ppages;

	/* The head iovec is straightforward, as it is already
	 * DMA-mapped. Sync the content that has changed.
	 */
	if (!rpcrdma_dma_map_regbuf(ia, rb))
		return false;
	sge_no = 1;
	sge[sge_no].addr = rdmab_addr(rb);
	sge[sge_no].length = xdr->head[0].iov_len;
	sge[sge_no].lkey = rdmab_lkey(rb);
	ib_dma_sync_single_for_device(rdmab_device(rb), sge[sge_no].addr,
				      sge[sge_no].length, DMA_TO_DEVICE);

	/* If there is a Read chunk, the page list is being handled
	 * via explicit RDMA, and thus is skipped here. However, the
	 * tail iovec may include an XDR pad for the page list, as
	 * well as additional content, and may not reside in the
	 * same page as the head iovec.
	 */
	if (rtype == rpcrdma_readch) {
		len = xdr->tail[0].iov_len;

		/* Do not include the tail if it is only an XDR pad */
		if (len < 4)
			goto out;

		page = virt_to_page(xdr->tail[0].iov_base);
		page_base = offset_in_page(xdr->tail[0].iov_base);

		/* If the content in the page list is an odd length,
		 * xdr_write_pages() has added a pad at the beginning
		 * of the tail iovec. Force the tail's non-pad content
		 * to land at the next XDR position in the Send message.
		 */
		page_base += len & 3;
		len -= len & 3;
		goto map_tail;
	}

	/* If there is a page list present, temporarily DMA map
	 * and prepare an SGE for each page to be sent.
	 */
	if (xdr->page_len) {
		ppages = xdr->pages + (xdr->page_base >> PAGE_SHIFT);
		page_base = offset_in_page(xdr->page_base);
		remaining = xdr->page_len;
		while (remaining) {
			sge_no++;
			if (sge_no > RPCRDMA_MAX_SEND_SGES - 2)
				goto out_mapping_overflow;

			len = min_t(u32, PAGE_SIZE - page_base, remaining);
			sge[sge_no].addr = ib_dma_map_page(device, *ppages,
							   page_base, len,
							   DMA_TO_DEVICE);
			if (ib_dma_mapping_error(device, sge[sge_no].addr))
				goto out_mapping_err;
			sge[sge_no].length = len;
			sge[sge_no].lkey = lkey;

			req->rl_mapped_sges++;
			ppages++;
			remaining -= len;
			page_base = 0;
		}
	}

	/* The tail iovec is not always constructed in the same
	 * page where the head iovec resides (see, for example,
	 * gss_wrap_req_priv). To neatly accommodate that case,
	 * DMA map it separately.
	 */
	if (xdr->tail[0].iov_len) {
		page = virt_to_page(xdr->tail[0].iov_base);
		page_base = offset_in_page(xdr->tail[0].iov_base);
		len = xdr->tail[0].iov_len;

map_tail:
		sge_no++;
		sge[sge_no].addr = ib_dma_map_page(device, page,
						   page_base, len,
						   DMA_TO_DEVICE);
		if (ib_dma_mapping_error(device, sge[sge_no].addr))
			goto out_mapping_err;
		sge[sge_no].length = len;
		sge[sge_no].lkey = lkey;
		req->rl_mapped_sges++;
	}

out:
	req->rl_send_wr.num_sge = sge_no + 1;
	return true;

out_mapping_overflow:
	pr_err("rpcrdma: too many Send SGEs (%u)\n", sge_no);
	return false;

out_mapping_err:
	pr_err("rpcrdma: Send mapping error\n");
	return false;
}

bool
rpcrdma_prepare_send_sges(struct rpcrdma_ia *ia, struct rpcrdma_req *req,
			  u32 hdrlen, struct xdr_buf *xdr,
			  enum rpcrdma_chunktype rtype)
{
	req->rl_send_wr.num_sge = 0;
	req->rl_mapped_sges = 0;

	if (!rpcrdma_prepare_hdr_sge(ia, req, hdrlen))
		goto out_map;

	if (rtype != rpcrdma_areadch)
		if (!rpcrdma_prepare_msg_sges(ia, req, xdr, rtype))
			goto out_map;

	return true;

out_map:
	pr_err("rpcrdma: failed to DMA map a Send buffer\n");
	return false;
}

void
rpcrdma_unmap_sges(struct rpcrdma_ia *ia, struct rpcrdma_req *req)
{
	struct ib_device *device = ia->ri_device;
	struct ib_sge *sge;
	int count;

	sge = &req->rl_send_sge[2];
	for (count = req->rl_mapped_sges; count--; sge++)
		ib_dma_unmap_page(device, sge->addr, sge->length,
				  DMA_TO_DEVICE);
	req->rl_mapped_sges = 0;
}

/**
 * rpcrdma_marshal_req - Marshal and send one RPC request
 * @r_xprt: controlling transport
 * @rqst: RPC request to be marshaled
 *
 * For the RPC in "rqst", this function:
 *  - Chooses the transfer mode (eg., RDMA_MSG or RDMA_NOMSG)
 *  - Registers Read, Write, and Reply chunks
 *  - Constructs the transport header
 *  - Posts a Send WR to send the transport header and request
 *
 * Returns:
 *	%0 if the RPC was sent successfully,
 *	%-ENOTCONN if the connection was lost,
 *	%-EAGAIN if not enough pages are available for on-demand reply buffer,
 *	%-ENOBUFS if no MRs are available to register chunks,
 *	%-EMSGSIZE if the transport header is too small,
 *	%-EIO if a permanent problem occurred while marshaling.
 */
int
rpcrdma_marshal_req(struct rpcrdma_xprt *r_xprt, struct rpc_rqst *rqst)
{
	struct rpcrdma_req *req = rpcr_to_rdmar(rqst);
	struct xdr_stream *xdr = &req->rl_stream;
	enum rpcrdma_chunktype rtype, wtype;
	bool ddp_allowed;
	__be32 *p;
	int ret;

#if defined(CONFIG_SUNRPC_BACKCHANNEL)
	if (test_bit(RPC_BC_PA_IN_USE, &rqst->rq_bc_pa_state))
		return rpcrdma_bc_marshal_reply(rqst);
#endif

	rpcrdma_set_xdrlen(&req->rl_hdrbuf, 0);
	xdr_init_encode(xdr, &req->rl_hdrbuf,
			req->rl_rdmabuf->rg_base);

	/* Fixed header fields */
	ret = -EMSGSIZE;
	p = xdr_reserve_space(xdr, 4 * sizeof(*p));
	if (!p)
		goto out_err;
	*p++ = rqst->rq_xid;
	*p++ = rpcrdma_version;
	*p++ = cpu_to_be32(r_xprt->rx_buf.rb_max_requests);

	/* When the ULP employs a GSS flavor that guarantees integrity
	 * or privacy, direct data placement of individual data items
	 * is not allowed.
	 */
	ddp_allowed = !(rqst->rq_cred->cr_auth->au_flags &
						RPCAUTH_AUTH_DATATOUCH);

	/*
	 * Chunks needed for results?
	 *
	 * o If the expected result is under the inline threshold, all ops
	 *   return as inline.
	 * o Large read ops return data as write chunk(s), header as
	 *   inline.
	 * o Large non-read ops return as a single reply chunk.
	 */
	if (rpcrdma_results_inline(r_xprt, rqst))
		wtype = rpcrdma_noch;
	else if (ddp_allowed && rqst->rq_rcv_buf.flags & XDRBUF_READ)
		wtype = rpcrdma_writech;
	else
		wtype = rpcrdma_replych;

	/*
	 * Chunks needed for arguments?
	 *
	 * o If the total request is under the inline threshold, all ops
	 *   are sent as inline.
	 * o Large write ops transmit data as read chunk(s), header as
	 *   inline.
	 * o Large non-write ops are sent with the entire message as a
	 *   single read chunk (protocol 0-position special case).
	 *
	 * This assumes that the upper layer does not present a request
	 * that both has a data payload, and whose non-data arguments
	 * by themselves are larger than the inline threshold.
	 */
	if (rpcrdma_args_inline(r_xprt, rqst)) {
		*p++ = rdma_msg;
		rtype = rpcrdma_noch;
	} else if (ddp_allowed && rqst->rq_snd_buf.flags & XDRBUF_WRITE) {
		*p++ = rdma_msg;
		rtype = rpcrdma_readch;
	} else {
		r_xprt->rx_stats.nomsg_call_count++;
		*p++ = rdma_nomsg;
		rtype = rpcrdma_areadch;
	}

	/* This implementation supports the following combinations
	 * of chunk lists in one RPC-over-RDMA Call message:
	 *
	 *   - Read list
	 *   - Write list
	 *   - Reply chunk
	 *   - Read list + Reply chunk
	 *
	 * It might not yet support the following combinations:
	 *
	 *   - Read list + Write list
	 *
	 * It does not support the following combinations:
	 *
	 *   - Write list + Reply chunk
	 *   - Read list + Write list + Reply chunk
	 *
	 * This implementation supports only a single chunk in each
	 * Read or Write list. Thus for example the client cannot
	 * send a Call message with a Position Zero Read chunk and a
	 * regular Read chunk at the same time.
	 */
	if (rtype != rpcrdma_noch) {
		ret = rpcrdma_encode_read_list(r_xprt, req, rqst, rtype);
		if (ret)
			goto out_err;
	}
	ret = encode_item_not_present(xdr);
	if (ret)
		goto out_err;

	if (wtype == rpcrdma_writech) {
		ret = rpcrdma_encode_write_list(r_xprt, req, rqst, wtype);
		if (ret)
			goto out_err;
	}
	ret = encode_item_not_present(xdr);
	if (ret)
		goto out_err;

	if (wtype != rpcrdma_replych)
		ret = encode_item_not_present(xdr);
	else
		ret = rpcrdma_encode_reply_chunk(r_xprt, req, rqst, wtype);
	if (ret)
		goto out_err;

	dprintk("RPC: %5u %s: %s/%s: hdrlen %u rpclen\n",
		rqst->rq_task->tk_pid, __func__,
		transfertypes[rtype], transfertypes[wtype],
		xdr_stream_pos(xdr));

	if (!rpcrdma_prepare_send_sges(&r_xprt->rx_ia, req,
				       xdr_stream_pos(xdr),
				       &rqst->rq_snd_buf, rtype)) {
		ret = -EIO;
		goto out_err;
	}
	return 0;

out_err:
	if (ret != -ENOBUFS) {
		pr_err("rpcrdma: header marshaling failed (%d)\n", ret);
		r_xprt->rx_stats.failed_marshal_count++;
	}
	return ret;
}

/**
 * rpcrdma_inline_fixup - Scatter inline received data into rqst's iovecs
 * @rqst: controlling RPC request
 * @srcp: points to RPC message payload in receive buffer
 * @copy_len: remaining length of receive buffer content
 * @pad: Write chunk pad bytes needed (zero for pure inline)
 *
 * The upper layer has set the maximum number of bytes it can
 * receive in each component of rq_rcv_buf. These values are set in
 * the head.iov_len, page_len, tail.iov_len, and buflen fields.
 *
 * Unlike the TCP equivalent (xdr_partial_copy_from_skb), in
 * many cases this function simply updates iov_base pointers in
 * rq_rcv_buf to point directly to the received reply data, to
 * avoid copying reply data.
 *
 * Returns the count of bytes which had to be memcopied.
 */
static unsigned long
rpcrdma_inline_fixup(struct rpc_rqst *rqst, char *srcp, int copy_len, int pad)
{
	unsigned long fixup_copy_count;
	int i, npages, curlen;
	char *destp;
	struct page **ppages;
	int page_base;

	/* The head iovec is redirected to the RPC reply message
	 * in the receive buffer, to avoid a memcopy.
	 */
	rqst->rq_rcv_buf.head[0].iov_base = srcp;
	rqst->rq_private_buf.head[0].iov_base = srcp;

	/* The contents of the receive buffer that follow
	 * head.iov_len bytes are copied into the page list.
	 */
	curlen = rqst->rq_rcv_buf.head[0].iov_len;
	if (curlen > copy_len)
		curlen = copy_len;
	dprintk("RPC:       %s: srcp 0x%p len %d hdrlen %d\n",
		__func__, srcp, copy_len, curlen);
	srcp += curlen;
	copy_len -= curlen;

	ppages = rqst->rq_rcv_buf.pages +
		(rqst->rq_rcv_buf.page_base >> PAGE_SHIFT);
	page_base = offset_in_page(rqst->rq_rcv_buf.page_base);
	fixup_copy_count = 0;
	if (copy_len && rqst->rq_rcv_buf.page_len) {
		int pagelist_len;

		pagelist_len = rqst->rq_rcv_buf.page_len;
		if (pagelist_len > copy_len)
			pagelist_len = copy_len;
		npages = PAGE_ALIGN(page_base + pagelist_len) >> PAGE_SHIFT;
		for (i = 0; i < npages; i++) {
			curlen = PAGE_SIZE - page_base;
			if (curlen > pagelist_len)
				curlen = pagelist_len;

			dprintk("RPC:       %s: page %d"
				" srcp 0x%p len %d curlen %d\n",
				__func__, i, srcp, copy_len, curlen);
			destp = kmap_atomic(ppages[i]);
			memcpy(destp + page_base, srcp, curlen);
			flush_dcache_page(ppages[i]);
			kunmap_atomic(destp);
			srcp += curlen;
			copy_len -= curlen;
			fixup_copy_count += curlen;
			pagelist_len -= curlen;
			if (!pagelist_len)
				break;
			page_base = 0;
		}

		/* Implicit padding for the last segment in a Write
		 * chunk is inserted inline at the front of the tail
		 * iovec. The upper layer ignores the content of
		 * the pad. Simply ensure inline content in the tail
		 * that follows the Write chunk is properly aligned.
		 */
		if (pad)
			srcp -= pad;
	}

	/* The tail iovec is redirected to the remaining data
	 * in the receive buffer, to avoid a memcopy.
	 */
	if (copy_len || pad) {
		rqst->rq_rcv_buf.tail[0].iov_base = srcp;
		rqst->rq_private_buf.tail[0].iov_base = srcp;
	}

	return fixup_copy_count;
}

/* Caller must guarantee @rep remains stable during this call.
 */
static void
rpcrdma_mark_remote_invalidation(struct list_head *mws,
				 struct rpcrdma_rep *rep)
{
	struct rpcrdma_mw *mw;

	if (!(rep->rr_wc_flags & IB_WC_WITH_INVALIDATE))
		return;

	list_for_each_entry(mw, mws, mw_list)
		if (mw->mw_handle == rep->rr_inv_rkey) {
			mw->mw_flags = RPCRDMA_MW_F_RI;
			break; /* only one invalidated MR per RPC */
		}
}

/* By convention, backchannel calls arrive via rdma_msg type
 * messages, and never populate the chunk lists. This makes
 * the RPC/RDMA header small and fixed in size, so it is
 * straightforward to check the RPC header's direction field.
 */
static bool
rpcrdma_is_bcall(struct rpcrdma_xprt *r_xprt, struct rpcrdma_rep *rep,
		 __be32 xid, __be32 proc)
#if defined(CONFIG_SUNRPC_BACKCHANNEL)
{
	struct xdr_stream *xdr = &rep->rr_stream;
	__be32 *p;

	if (proc != rdma_msg)
		return false;

	/* Peek at stream contents without advancing. */
	p = xdr_inline_decode(xdr, 0);

	/* Chunk lists */
	if (*p++ != xdr_zero)
		return false;
	if (*p++ != xdr_zero)
		return false;
	if (*p++ != xdr_zero)
		return false;

	/* RPC header */
	if (*p++ != xid)
		return false;
	if (*p != cpu_to_be32(RPC_CALL))
		return false;

	/* Now that we are sure this is a backchannel call,
	 * advance to the RPC header.
	 */
	p = xdr_inline_decode(xdr, 3 * sizeof(*p));
	if (unlikely(!p))
		goto out_short;

	rpcrdma_bc_receive_call(r_xprt, rep);
	return true;

out_short:
	pr_warn("RPC/RDMA short backward direction call\n");
	if (rpcrdma_ep_post_recv(&r_xprt->rx_ia, rep))
		xprt_disconnect_done(&r_xprt->rx_xprt);
	return true;
}
#else	/* CONFIG_SUNRPC_BACKCHANNEL */
{
	return false;
}
#endif	/* CONFIG_SUNRPC_BACKCHANNEL */

static int decode_rdma_segment(struct xdr_stream *xdr, u32 *length)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, 4 * sizeof(*p));
	if (unlikely(!p))
		return -EIO;

	ifdebug(FACILITY) {
		u64 offset;
		u32 handle;

		handle = be32_to_cpup(p++);
		*length = be32_to_cpup(p++);
		xdr_decode_hyper(p, &offset);
		dprintk("RPC:       %s:   segment %u@0x%016llx:0x%08x\n",
			__func__, *length, (unsigned long long)offset,
			handle);
	} else {
		*length = be32_to_cpup(p + 1);
	}

	return 0;
}

static int decode_write_chunk(struct xdr_stream *xdr, u32 *length)
{
	u32 segcount, seglength;
	__be32 *p;

	p = xdr_inline_decode(xdr, sizeof(*p));
	if (unlikely(!p))
		return -EIO;

	*length = 0;
	segcount = be32_to_cpup(p);
	while (segcount--) {
		if (decode_rdma_segment(xdr, &seglength))
			return -EIO;
		*length += seglength;
	}

	dprintk("RPC:       %s: segcount=%u, %u bytes\n",
		__func__, be32_to_cpup(p), *length);
	return 0;
}

/* In RPC-over-RDMA Version One replies, a Read list is never
 * expected. This decoder is a stub that returns an error if
 * a Read list is present.
 */
static int decode_read_list(struct xdr_stream *xdr)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, sizeof(*p));
	if (unlikely(!p))
		return -EIO;
	if (unlikely(*p != xdr_zero))
		return -EIO;
	return 0;
}

/* Supports only one Write chunk in the Write list
 */
static int decode_write_list(struct xdr_stream *xdr, u32 *length)
{
	u32 chunklen;
	bool first;
	__be32 *p;

	*length = 0;
	first = true;
	do {
		p = xdr_inline_decode(xdr, sizeof(*p));
		if (unlikely(!p))
			return -EIO;
		if (*p == xdr_zero)
			break;
		if (!first)
			return -EIO;

		if (decode_write_chunk(xdr, &chunklen))
			return -EIO;
		*length += chunklen;
		first = false;
	} while (true);
	return 0;
}

static int decode_reply_chunk(struct xdr_stream *xdr, u32 *length)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, sizeof(*p));
	if (unlikely(!p))
		return -EIO;

	*length = 0;
	if (*p != xdr_zero)
		if (decode_write_chunk(xdr, length))
			return -EIO;
	return 0;
}

static int
rpcrdma_decode_msg(struct rpcrdma_xprt *r_xprt, struct rpcrdma_rep *rep,
		   struct rpc_rqst *rqst)
{
	struct xdr_stream *xdr = &rep->rr_stream;
	u32 writelist, replychunk, rpclen;
	char *base;

	/* Decode the chunk lists */
	if (decode_read_list(xdr))
		return -EIO;
	if (decode_write_list(xdr, &writelist))
		return -EIO;
	if (decode_reply_chunk(xdr, &replychunk))
		return -EIO;

	/* RDMA_MSG sanity checks */
	if (unlikely(replychunk))
		return -EIO;

	/* Build the RPC reply's Payload stream in rqst->rq_rcv_buf */
	base = (char *)xdr_inline_decode(xdr, 0);
	rpclen = xdr_stream_remaining(xdr);
	r_xprt->rx_stats.fixup_copy_count +=
		rpcrdma_inline_fixup(rqst, base, rpclen, writelist & 3);

	r_xprt->rx_stats.total_rdma_reply += writelist;
	return rpclen + xdr_align_size(writelist);
}

static noinline int
rpcrdma_decode_nomsg(struct rpcrdma_xprt *r_xprt, struct rpcrdma_rep *rep)
{
	struct xdr_stream *xdr = &rep->rr_stream;
	u32 writelist, replychunk;

	/* Decode the chunk lists */
	if (decode_read_list(xdr))
		return -EIO;
	if (decode_write_list(xdr, &writelist))
		return -EIO;
	if (decode_reply_chunk(xdr, &replychunk))
		return -EIO;

	/* RDMA_NOMSG sanity checks */
	if (unlikely(writelist))
		return -EIO;
	if (unlikely(!replychunk))
		return -EIO;

	/* Reply chunk buffer already is the reply vector */
	r_xprt->rx_stats.total_rdma_reply += replychunk;
	return replychunk;
}

static noinline int
rpcrdma_decode_error(struct rpcrdma_xprt *r_xprt, struct rpcrdma_rep *rep,
		     struct rpc_rqst *rqst)
{
	struct xdr_stream *xdr = &rep->rr_stream;
	__be32 *p;

	p = xdr_inline_decode(xdr, sizeof(*p));
	if (unlikely(!p))
		return -EIO;

	switch (*p) {
	case err_vers:
		p = xdr_inline_decode(xdr, 2 * sizeof(*p));
		if (!p)
			break;
		dprintk("RPC: %5u: %s: server reports version error (%u-%u)\n",
			rqst->rq_task->tk_pid, __func__,
			be32_to_cpup(p), be32_to_cpu(*(p + 1)));
		break;
	case err_chunk:
		dprintk("RPC: %5u: %s: server reports header decoding error\n",
			rqst->rq_task->tk_pid, __func__);
		break;
	default:
		dprintk("RPC: %5u: %s: server reports unrecognized error %d\n",
			rqst->rq_task->tk_pid, __func__, be32_to_cpup(p));
	}

	r_xprt->rx_stats.bad_reply_count++;
	return -EREMOTEIO;
}

/* Process received RPC/RDMA messages.
 *
 * Errors must result in the RPC task either being awakened, or
 * allowed to timeout, to discover the errors at that time.
 */
void
rpcrdma_reply_handler(struct work_struct *work)
{
	struct rpcrdma_rep *rep =
			container_of(work, struct rpcrdma_rep, rr_work);
	struct rpcrdma_xprt *r_xprt = rep->rr_rxprt;
	struct rpc_xprt *xprt = &r_xprt->rx_xprt;
	struct xdr_stream *xdr = &rep->rr_stream;
	struct rpcrdma_req *req;
	struct rpc_rqst *rqst;
	__be32 *p, xid, vers, proc;
	unsigned long cwnd;
	int status;

	dprintk("RPC:       %s: incoming rep %p\n", __func__, rep);

	if (rep->rr_hdrbuf.head[0].iov_len == 0)
		goto out_badstatus;

	xdr_init_decode(xdr, &rep->rr_hdrbuf,
			rep->rr_hdrbuf.head[0].iov_base);

	/* Fixed transport header fields */
	p = xdr_inline_decode(xdr, 4 * sizeof(*p));
	if (unlikely(!p))
		goto out_shortreply;
	xid = *p++;
	vers = *p++;
	p++;	/* credits */
	proc = *p++;

	if (rpcrdma_is_bcall(r_xprt, rep, xid, proc))
		return;

	/* Match incoming rpcrdma_rep to an rpcrdma_req to
	 * get context for handling any incoming chunks.
	 */
	spin_lock(&xprt->recv_lock);
	rqst = xprt_lookup_rqst(xprt, xid);
	if (!rqst)
		goto out_norqst;
	xprt_pin_rqst(rqst);
	spin_unlock(&xprt->recv_lock);
	req = rpcr_to_rdmar(rqst);
	req->rl_reply = rep;

	dprintk("RPC:       %s: reply %p completes request %p (xid 0x%08x)\n",
		__func__, rep, req, be32_to_cpu(xid));

	/* Invalidate and unmap the data payloads before waking the
	 * waiting application. This guarantees the memory regions
	 * are properly fenced from the server before the application
	 * accesses the data. It also ensures proper send flow control:
	 * waking the next RPC waits until this RPC has relinquished
	 * all its Send Queue entries.
	 */
	if (!list_empty(&req->rl_registered)) {
		rpcrdma_mark_remote_invalidation(&req->rl_registered, rep);
		r_xprt->rx_ia.ri_ops->ro_unmap_sync(r_xprt,
						    &req->rl_registered);
	}

	xprt->reestablish_timeout = 0;
	if (vers != rpcrdma_version)
		goto out_badversion;

	switch (proc) {
	case rdma_msg:
		status = rpcrdma_decode_msg(r_xprt, rep, rqst);
		break;
	case rdma_nomsg:
		status = rpcrdma_decode_nomsg(r_xprt, rep);
		break;
	case rdma_error:
		status = rpcrdma_decode_error(r_xprt, rep, rqst);
		break;
	default:
		status = -EIO;
	}
	if (status < 0)
		goto out_badheader;

out:
	spin_lock(&xprt->recv_lock);
	cwnd = xprt->cwnd;
	xprt->cwnd = atomic_read(&r_xprt->rx_buf.rb_credits) << RPC_CWNDSHIFT;
	if (xprt->cwnd > cwnd)
		xprt_release_rqst_cong(rqst->rq_task);

	xprt_complete_rqst(rqst->rq_task, status);
	xprt_unpin_rqst(rqst);
	spin_unlock(&xprt->recv_lock);
	dprintk("RPC:       %s: xprt_complete_rqst(0x%p, 0x%p, %d)\n",
		__func__, xprt, rqst, status);
	return;

out_badstatus:
	rpcrdma_recv_buffer_put(rep);
	if (r_xprt->rx_ep.rep_connected == 1) {
		r_xprt->rx_ep.rep_connected = -EIO;
		rpcrdma_conn_func(&r_xprt->rx_ep);
	}
	return;

/* If the incoming reply terminated a pending RPC, the next
 * RPC call will post a replacement receive buffer as it is
 * being marshaled.
 */
out_badversion:
	dprintk("RPC:       %s: invalid version %d\n",
		__func__, be32_to_cpu(vers));
	status = -EIO;
	r_xprt->rx_stats.bad_reply_count++;
	goto out;

out_badheader:
	dprintk("RPC: %5u %s: invalid rpcrdma reply (type %u)\n",
		rqst->rq_task->tk_pid, __func__, be32_to_cpu(proc));
	r_xprt->rx_stats.bad_reply_count++;
	status = -EIO;
	goto out;

/* The req was still available, but by the time the recv_lock
 * was acquired, the rqst and task had been released. Thus the RPC
 * has already been terminated.
 */
out_norqst:
	spin_unlock(&xprt->recv_lock);
	dprintk("RPC:       %s: no match for incoming xid 0x%08x\n",
		__func__, be32_to_cpu(xid));
	goto repost;

out_shortreply:
	dprintk("RPC:       %s: short/invalid reply\n", __func__);
	goto repost;

/* If no pending RPC transaction was matched, post a replacement
 * receive buffer before returning.
 */
repost:
	r_xprt->rx_stats.bad_reply_count++;
	if (rpcrdma_ep_post_recv(&r_xprt->rx_ia, rep))
		rpcrdma_recv_buffer_put(rep);
}
