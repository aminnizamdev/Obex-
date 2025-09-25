use crate::{types::Ticket, errors::Step1Error};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parameters for creating a ticket
#[derive(Debug, Clone, Copy)]
pub struct TicketParams {
    pub chain_id: [u8; 32],
    pub epoch_number: u64,
    pub epoch_hash: [u8; 32],
    pub epoch_nonce: [u8; 32],
    pub pk: [u8; 32],
    pub root: [u8; 32],
    pub valid_from: Option<u64>,
    pub valid_duration_secs: u64,
}

/// Verify a ticket's time validity.
///
/// # Errors
///
/// Returns `Step1Error::InvalidTicketWindow` if the ticket is outside its valid time window.
pub fn verify_ticket_time(
    ticket: &Ticket,
    current_time: Option<u64>
) -> Result<(), Step1Error> {
    let now = current_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    
    if now < ticket.valid_from {
        return Err(Step1Error::TicketExpired {
            timestamp: ticket.valid_from,
            current_time: now,
            window: 0
        });
    }
    
    if now > ticket.valid_to {
        return Err(Step1Error::TicketExpired {
            timestamp: ticket.valid_to,
            current_time: now,
            window: 0
        });
    }
    
    Ok(())
}

/// Create a ticket with specified validity period.
#[must_use]
pub fn create_ticket(params: TicketParams) -> Ticket {
    let valid_from = params.valid_from.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    
    Ticket {
        chain_id: params.chain_id,
        epoch_number: params.epoch_number,
        epoch_hash: params.epoch_hash,
        epoch_nonce: params.epoch_nonce,
        pk: params.pk,
        root: params.root,
        valid_from,
        valid_to: valid_from + params.valid_duration_secs,
    }
}

/// Batch verify multiple tickets.
#[must_use]
pub fn verify_tickets_batch(
    tickets: &[Ticket],
    current_time: Option<u64>
) -> Vec<bool> {
    let mut results = Vec::with_capacity(tickets.len());
    
    for ticket in tickets {
        let is_valid = verify_ticket_time(ticket, current_time).is_ok();
        results.push(is_valid);
    }
    
    results
}

/// Check if a ticket is within the valid time window.
#[must_use]
pub fn is_ticket_valid_time(ticket: &Ticket, current_time: Option<u64>) -> bool {
    let now = current_time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });
    
    now >= ticket.valid_from && now <= ticket.valid_to
}